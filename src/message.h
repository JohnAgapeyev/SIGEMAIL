#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint>
#include <optional>

#include "crypto.h"

struct signal_message {
    struct header {
        crypto::secure_array<std::byte, 32> dh_public_key;
        uint64_t prev_chain_len;
        uint64_t message_num;
    } header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;
};

struct initial_signal_message {
    struct header {
        crypto::secure_array<std::byte, 32> identity_key;
        crypto::secure_array<std::byte, 32> ephemeral_key;
        //This is the public key of the one-time key that was used in the initial message
        std::optional<crypto::secure_array<std::byte, 32>> remote_one_time_public_key;
    } header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;
};

#endif /* end of include guard: MESSAGE_H */
