#include <cstdint>
#include <optional>

#include "crypto.h"
#include "logging.h"
#include "message.h"
#include "session.h"

const uint64_t MAX_SKIP = 100;

session::session(crypto::shared_key shared_secret, crypto::public_key dest_public_key,
        crypto::public_key initial_id_public, crypto::public_key initial_ephem_public,
        std::optional<crypto::public_key> initial_otpk_public) :
        self_keypair(),
        remote_public_key(std::move(dest_public_key)), root_key(shared_secret),
        send_chain_key(crypto::root_derive(
                root_key, self_keypair.generate_shared_secret(remote_public_key))),
        initial_header_contents({std::move(initial_id_public), std::move(initial_ephem_public),
                std::move(initial_otpk_public)}),
        initial_secret_key(std::move(shared_secret)) {}

session::session(crypto::shared_key shared_secret, crypto::DH_Keypair self_kp) :
        self_keypair(std::move(self_kp)), root_key(std::move(shared_secret)),
        initial_header_contents(std::nullopt), initial_secret_key(std::nullopt) {}

const signal_message session::ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::byte>& aad) {
    //initial_header_contents = std::nullopt;
    //initial_secret_key = std::nullopt;

    if (!initial_header_contents.has_value()) {
        spdlog::debug("Session encrypt pre send chain {}", send_chain_key);
        const auto message_key = crypto::chain_derive(send_chain_key);
        spdlog::debug("Session encrypt resulting message key {}", message_key);
        spdlog::debug("Session encrypt Post send chain {}", send_chain_key);

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
        spdlog::debug("Session encrypt pre initial chain {}", send_chain_key);
        const auto message_key = *initial_secret_key;
        spdlog::debug("Session encrypt initial message key {}", message_key);

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
        spdlog::debug("Session decrypt pre ratchet chain {}", receive_chain_key);
        if (header.dh_public_key != remote_public_key) {
            spdlog::info("We're ratcheting");
            skip_message_keys(header.prev_chain_len);
            DH_ratchet(header.dh_public_key);
        }
        spdlog::info("Skipping {}", header.message_num);
        skip_message_keys(header.message_num);
        spdlog::debug("Session decrypt receive chain {}", receive_chain_key);
        const auto message_key = crypto::chain_derive(receive_chain_key);
        spdlog::debug("Session decrypt resulting key {}", message_key);
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

    //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
    auto message_copy = message.message;
    return {{secret_key, prekey}, crypto::decrypt(message_copy, secret_key, message.aad)};
}

std::pair<session, crypto::secure_vector<std::byte>> decrypt_initial_message(
        const signal_message& message, const crypto::DH_Keypair& identity,
        const crypto::DH_Keypair& prekey) {
    const auto header = std::get<initial_message_header>(message.header);

    const auto secret_key
            = X3DH_receiver(identity, prekey, header.identity_key, header.ephemeral_key);

    //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
    auto message_copy = message.message;
    return {{secret_key, prekey}, crypto::decrypt(message_copy, secret_key, message.aad)};
}
