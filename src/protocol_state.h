#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include "crypto.h"
#include "dh.h"

class session_state {
public:
    session_state() = default;
    ~session_state() = default;
    session_state(const session_state&) = default;
    session_state(session_state&&) = default;
    session_state& operator=(session_state&&) = default;
    session_state& operator=(const session_state&) = default;

private:
    crypto::DH_Keypair self_keypair;
    crypto::secure_array<std::byte, 32> remote_public_key;
    crypto::secure_array<std::byte, 32> root_key;
    crypto::secure_array<std::byte, 32> send_chain_key;
    crypto::secure_array<std::byte, 32> receive_chain_key;
    uint64_t send_message_num;
    uint64_t receive_message_num;
    uint64_t previous_send_chain_size;

    crypto::secure_unordered_map<std::pair<crypto::secure_array<std::byte, 32>, uint64_t>,
        crypto::secure_array<std::byte, 32>> skipped_keys;
};

#endif /* end of include guard: PROTOCOL_STATE_H */
