#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint>
#include <optional>

#include "crypto.h"

struct signal_message {
    struct header {
        crypto::public_key dh_public_key;
        uint64_t prev_chain_len;
        uint64_t message_num;
    } header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;
};

struct initial_signal_message {
    struct header {
        crypto::public_key identity_key;
        crypto::public_key ephemeral_key;
        //This is the public key of the one-time key that was used in the initial message
        std::optional<crypto::public_key> remote_one_time_public_key;
    } header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;
};

#endif /* end of include guard: MESSAGE_H */
