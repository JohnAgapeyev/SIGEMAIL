#include <cstdint>
#include <optional>

#include "crypto.h"
#include "logging.h"
#include "message.h"
#include "session.h"

const uint64_t MAX_SKIP = 100;

session::session(crypto::shared_key shared_secret, crypto::DH_Keypair self_ephem,
        crypto::public_key dest_public_key, crypto::public_key initial_id_public,
        std::optional<crypto::public_key> initial_otpk_public, std::vector<std::byte> aad) :
        self_keypair(std::move(self_ephem)),
        remote_public_key(std::move(dest_public_key)), root_key(shared_secret),
        x3dh_aad(std::move(aad)),
        //send_chain_key(crypto::root_derive(
        //root_key, self_keypair.generate_shared_secret(remote_public_key))),
        initial_header_contents({std::move(initial_id_public), self_keypair.get_public(),
                std::move(initial_otpk_public)}),
        initial_secret_key(std::move(shared_secret)) {
    send_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));

    //This gives me a nonzero initial receive chain key that relies on the inital secret key
    //but in a way that the recipient can generate without awkward issues
    receive_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));
}

session::session(crypto::shared_key shared_secret, crypto::DH_Keypair self_kp,
        crypto::public_key dest_public_key, std::vector<std::byte> aad) :
        self_keypair(std::move(self_kp)),
        remote_public_key(std::move(dest_public_key)), root_key(std::move(shared_secret)),
        x3dh_aad(std::move(aad)),
        //receive_chain_key(crypto::root_derive(
        //root_key, self_keypair.generate_shared_secret(remote_public_key))),
        initial_header_contents(std::nullopt), initial_secret_key(std::nullopt) {
    receive_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));

    //This gives me a nonzero initial receive chain key that relies on the inital secret key
    //but in a way that the recipient can generate without awkward issues
    send_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));
}

const signal_message session::ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
        crypto::secure_vector<std::byte> aad) {
    aad.insert(aad.end(), x3dh_aad.begin(), x3dh_aad.end());

    if (!initial_header_contents.has_value()) {
        const auto message_key = crypto::chain_derive(send_chain_key);

        const signal_message m = [this, &message_key, &plaintext, &aad]() {
            signal_message result;
            message_header h;
            h.dh_public_key = self_keypair.get_public();
            h.prev_chain_len = previous_send_chain_size;
            h.message_num = send_message_num;
            result.header = h;
            result.message = crypto::encrypt(plaintext, message_key, aad);
            result.aad = crypto::secure_vector<std::byte>{aad};
            return result;
        }();

        ++send_message_num;

        return m;
    } else {
        const auto message_key = *initial_secret_key;

        const signal_message m = [this, &message_key, &plaintext, &aad]() {
            signal_message result;
            initial_message_header h;
            h.identity_key = initial_header_contents->identity_key;
            h.ephemeral_key = initial_header_contents->ephemeral_key;
            h.remote_one_time_public_key = initial_header_contents->remote_one_time_public_key;
            result.header = h;
            result.message = crypto::encrypt(plaintext, message_key, aad);
            result.aad = crypto::secure_vector<std::byte>{aad};
            return result;
        }();

        initial_header_contents = std::nullopt;
        initial_secret_key = std::nullopt;

        return m;
    }
}

const crypto::secure_vector<std::byte> session::ratchet_decrypt(const signal_message& message) {
    //Save state
    const auto state_copy = *this;
    try {
        if (const auto skipped_result = try_skipped_message_keys(message);
                skipped_result.has_value()) {
            return *skipped_result;
        }
        const auto header = std::get<message_header>(message.header);
        if (header.dh_public_key != remote_public_key) {
            skip_message_keys(header.prev_chain_len);
            DH_ratchet(header.dh_public_key);
        }
        skip_message_keys(header.message_num);
        const auto message_key = crypto::chain_derive(receive_chain_key);
        ++receive_message_num;

        auto message_copy = message.message;
        return crypto::decrypt(message_copy, message_key, message.aad);
    } catch (...) {
        //I don't care whether this exception is intended or not, so catch all exceptions instead of just expected ones
        //Restore state
        *this = state_copy;
        throw;
    }
}

const std::optional<crypto::secure_vector<std::byte>> session::try_skipped_message_keys(
        const signal_message& message) {
    const auto header = std::get<message_header>(message.header);
    const auto dict_key = std::make_pair(header.dh_public_key, header.message_num);
    if (skipped_keys.find(dict_key) != skipped_keys.end()) {
        const auto message_key = skipped_keys[dict_key];
        skipped_keys.erase(dict_key);

        //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
        auto message_copy = message.message;
        return crypto::decrypt(message_copy, message_key, message.aad);
    } else {
        return std::nullopt;
    }
}

void session::skip_message_keys(uint64_t until) {
    if (receive_message_num + MAX_SKIP < until) {
        throw std::runtime_error(
                "Tried to generate more skipped keys than the previous chain contained");
    }
    if (receive_chain_key.empty()) {
        return;
    }
    while (receive_message_num < until) {
        const auto message_key = crypto::chain_derive(receive_chain_key);
        skipped_keys.emplace(std::make_pair(remote_public_key, receive_message_num), message_key);
        ++receive_message_num;
    }
}

void session::DH_ratchet(const crypto::public_key& remote_pub_key) {
    previous_send_chain_size = send_message_num;
    send_message_num = 0;
    receive_message_num = 0;
    remote_public_key = remote_pub_key;
    receive_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));
    self_keypair = crypto::DH_Keypair();
    send_chain_key
            = crypto::root_derive(root_key, self_keypair.generate_shared_secret(remote_public_key));
}

bool session::operator==(const session& other) const {
    if (self_keypair != other.self_keypair) {
        return false;
    }
    if (remote_public_key != other.remote_public_key) {
        return false;
    }
    if (root_key != other.root_key) {
        return false;
    }
    if (send_chain_key != other.send_chain_key) {
        return false;
    }
    if (receive_chain_key != other.receive_chain_key) {
        return false;
    }
    if (send_message_num != other.send_message_num) {
        return false;
    }
    if (receive_message_num != other.receive_message_num) {
        return false;
    }
    if (previous_send_chain_size != other.previous_send_chain_size) {
        return false;
    }
    if (skipped_keys != other.skipped_keys) {
        return false;
    }
    return true;
}

std::pair<session, crypto::secure_vector<std::byte>> decrypt_initial_message(
        const signal_message& message, const crypto::DH_Keypair& identity,
        const crypto::DH_Keypair& prekey, const crypto::DH_Keypair& one_time) {
    const auto header = std::get<initial_message_header>(message.header);

    const auto secret_key
            = X3DH_receiver(identity, prekey, one_time, header.identity_key, header.ephemeral_key);

    std::vector<std::byte> x3dh_aad;
    x3dh_aad.insert(x3dh_aad.end(), header.identity_key.begin(), header.identity_key.end());
    x3dh_aad.insert(x3dh_aad.end(), identity.get_public().begin(), identity.get_public().end());

    //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
    auto message_copy = message.message;
    return {{secret_key, prekey, header.ephemeral_key, x3dh_aad},
            crypto::decrypt(message_copy, secret_key, message.aad)};
}

std::pair<session, crypto::secure_vector<std::byte>> decrypt_initial_message(
        const signal_message& message, const crypto::DH_Keypair& identity,
        const crypto::DH_Keypair& prekey) {
    const auto header = std::get<initial_message_header>(message.header);

    const auto secret_key
            = X3DH_receiver(identity, prekey, header.identity_key, header.ephemeral_key);

    std::vector<std::byte> x3dh_aad;
    x3dh_aad.insert(x3dh_aad.end(), header.identity_key.begin(), header.identity_key.end());
    x3dh_aad.insert(x3dh_aad.end(), identity.get_public().begin(), identity.get_public().end());

    //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
    auto message_copy = message.message;
    return {{secret_key, prekey, header.ephemeral_key, x3dh_aad},
            crypto::decrypt(message_copy, secret_key, message.aad)};
}
