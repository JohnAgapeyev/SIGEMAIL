#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint>
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


#endif /* end of include guard: MESSAGE_H */
