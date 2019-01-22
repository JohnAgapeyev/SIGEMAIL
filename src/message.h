#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint>
#include <optional>

#include "crypto.h"

struct message_header {
    crypto::public_key dh_public_key;
    uint64_t prev_chain_len;
    uint64_t message_num;

    bool operator==(const message_header& other) const {
        return dh_public_key == other.dh_public_key && prev_chain_len == other.prev_chain_len
                && message_num == other.message_num;
    }
    bool operator!=(const message_header& other) const { return !(*this == other); }
};

struct initial_message_header {
    crypto::public_key identity_key;
    crypto::public_key ephemeral_key;
    //This is the public key of the one-time key that was used in the initial message
    std::optional<crypto::public_key> remote_one_time_public_key;

    bool operator==(const initial_message_header& other) const {
        return identity_key == other.identity_key && ephemeral_key == other.ephemeral_key
                && remote_one_time_public_key == other.remote_one_time_public_key;
    }
    bool operator!=(const initial_message_header& other) const { return !(*this == other); }
};

struct signal_message {
    std::variant<message_header, initial_message_header> header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;

    bool operator==(const signal_message& other) const {
        return header == other.header && message == other.message && aad == other.aad;
    }
    bool operator!=(const signal_message& other) const { return !(*this == other); }
};

std::string serialize_message(const signal_message& mesg);
signal_message deserialize_message(std::string mesg);

#endif /* end of include guard: MESSAGE_H */
