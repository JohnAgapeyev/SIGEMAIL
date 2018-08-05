#include <cstdint>
#include <optional>

#include "crypto.h"
#include "message.h"
#include "protocol.h"
#include "protocol_state.h"

const uint64_t MAX_SKIP = 100;

const signal_message ratchet_encrypt(session_state& state,
        const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::byte>& aad) {
    const auto message_key = crypto::chain_derive(state.send_chain_key);

    const signal_message m = [&]() {
        signal_message result;
        result.header.dh_public_key = state.self_keypair.get_public();
        result.header.prev_chain_len = state.previous_send_chain_size;
        result.header.message_num = state.send_message_num;
        crypto::encrypt(plaintext, message_key, aad, result.message);
        result.aad = crypto::secure_vector<std::byte>{aad};
        return result;
    }();

    ++state.send_message_num;

    return m;
}

const crypto::secure_vector<std::byte> ratchet_decrypt(
        session_state& state, const signal_message& message) {
    const auto state_copy = state;
    try {
        const auto skipped_result = try_skipped_message_keys(state, message);
        if (skipped_result.has_value()) {
            return *skipped_result;
        }
        if (message.header.dh_public_key != state.remote_public_key) {
            skip_message_keys(state, message.header.prev_chain_len);
            DH_ratchet(state, message.header.dh_public_key);
        }
        skip_message_keys(state, message.header.message_num);
        const auto message_key = crypto::chain_derive(state.receive_chain_key);
        ++state.receive_message_num;

        auto message_copy = message.message;
        crypto::secure_vector<std::byte> plaintext;
        if (!crypto::decrypt(message_copy, message_key, message.aad, plaintext)) {
            throw std::runtime_error("Message failed to decrypt");
        }

        return plaintext;
    } catch (std::runtime_error&) {
        state = state_copy;
        throw;
    }
}

const std::optional<crypto::secure_vector<std::byte>> try_skipped_message_keys(
        session_state& state, const signal_message& message) {
    const auto dict_key = std::make_pair(message.header.dh_public_key, message.header.message_num);
    if (state.skipped_keys.find(dict_key) != state.skipped_keys.end()) {
        const auto message_key = state.skipped_keys[dict_key];
        state.skipped_keys.erase(dict_key);

        //I don't like having to copy the message here, but the GCM set tag call in OpenSSL takes a non-const pointer to the tag
        auto message_copy = message.message;
        crypto::secure_vector<std::byte> plaintext;
        if (!crypto::decrypt(message_copy, message_key, message.aad, plaintext)) {
            throw std::runtime_error("Message failed to decrypt");
        }
        return plaintext;
    } else {
        return {};
    }
}

void skip_message_keys(session_state& state, uint64_t until) {
    if (state.receive_message_num + MAX_SKIP < until) {
        throw std::runtime_error(
                "Tried to generate more skipped keys than the previous chain contained");
    }
    if (state.receive_chain_key.empty()) {
        return;
    }
    while (state.receive_message_num < until) {
        const auto message_key = crypto::chain_derive(state.receive_chain_key);
        state.skipped_keys.emplace(
                std::make_pair(state.remote_public_key, state.receive_message_num), message_key);
        ++state.receive_message_num;
    }
}

void DH_ratchet(
        session_state& state, const crypto::secure_array<std::byte, 32>& remote_public_key) {
    state.previous_send_chain_size = state.send_message_num;
    state.send_message_num = 0;
    state.receive_message_num = 0;
    state.remote_public_key = remote_public_key;
    state.receive_chain_key = crypto::root_derive(
            state.root_key, state.self_keypair.generate_shared_secret(state.remote_public_key));
    state.self_keypair = crypto::DH_Keypair();
    state.send_chain_key = crypto::root_derive(
            state.root_key, state.self_keypair.generate_shared_secret(state.remote_public_key));
}

void ratchet_init_sender(session_state& state,
        const crypto::secure_array<std::byte, 32>& shared_secret,
        const crypto::secure_array<std::byte, 32>& dest_pulic_key) {
    state.self_keypair = crypto::DH_Keypair();
    state.remote_public_key = dest_pulic_key;

    //Initialize here for use in the root key derivation call
    state.root_key = shared_secret;

    state.send_chain_key = crypto::root_derive(
            state.root_key, state.self_keypair.generate_shared_secret(state.remote_public_key));

    state.receive_chain_key = {};

    state.send_message_num = 0;
    state.receive_message_num = 0;
    state.previous_send_chain_size = 0;

    state.skipped_keys = {};
}

void ratchet_init_receiver(session_state& state,
        const crypto::secure_array<std::byte, 32>& shared_secret,
        const crypto::DH_Keypair& self_keypair) {
    state.self_keypair = self_keypair;
    state.remote_public_key = {};

    //Initialize here for use in the root key derivation call
    state.root_key = shared_secret;

    state.send_chain_key = {};
    state.receive_chain_key = {};

    state.send_message_num = 0;
    state.receive_message_num = 0;
    state.previous_send_chain_size = 0;

    state.skipped_keys = {};
}
