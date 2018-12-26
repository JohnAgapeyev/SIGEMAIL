#include <cstdint>
#include <optional>

#include "crypto.h"
#include "message.h"
#include "session.h"

const uint64_t MAX_SKIP = 100;

session::session(crypto::shared_key shared_secret, crypto::public_key dest_public_key) :
        self_keypair(), remote_public_key(std::move(dest_public_key)),
        root_key(std::move(shared_secret)),
        send_chain_key(crypto::root_derive(
                root_key, self_keypair.generate_shared_secret(remote_public_key))) {}

session::session(crypto::shared_key shared_secret, crypto::DH_Keypair self_kp) :
        self_keypair(std::move(self_kp)), root_key(std::move(shared_secret)) {}

const signal_message session::ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::byte>& aad) {
    const auto message_key = crypto::chain_derive(send_chain_key);

    const signal_message m = [&]() {
        signal_message result;
        result.header.dh_public_key = self_keypair.get_public();
        result.header.prev_chain_len = previous_send_chain_size;
        result.header.message_num = send_message_num;
        result.message = crypto::encrypt(plaintext, message_key, aad);
        result.aad = crypto::secure_vector<std::byte>{aad};
        return result;
    }();

    ++send_message_num;

    return m;
}

const crypto::secure_vector<std::byte> session::ratchet_decrypt(const signal_message& message) {
    //Save state
    const auto state_copy = *this;
    try {
        if (const auto skipped_result = try_skipped_message_keys(message);
                skipped_result.has_value()) {
            return *skipped_result;
        }
        if (message.header.dh_public_key != remote_public_key) {
            skip_message_keys(message.header.prev_chain_len);
            DH_ratchet(message.header.dh_public_key);
        }
        skip_message_keys(message.header.message_num);
        const auto message_key = crypto::chain_derive(receive_chain_key);
        ++receive_message_num;

        auto message_copy = message.message;
        return crypto::decrypt(message_copy, message_key, message.aad);
    } catch (std::runtime_error&) {
        //Restore state
        *this = state_copy;
        throw;
    }
}

const std::optional<crypto::secure_vector<std::byte>> session::try_skipped_message_keys(
        const signal_message& message) {
    const auto dict_key = std::make_pair(message.header.dh_public_key, message.header.message_num);
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
