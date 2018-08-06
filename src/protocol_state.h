#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include <cstdint>
#include <optional>

#include "crypto.h"
#include "dh.h"
#include "message.h"
#include "protocol_state.h"

extern const uint64_t MAX_SKIP;

class session_state {
public:
    //Sender initialization
    session_state(crypto::secure_array<std::byte, 32>& shared_secret,
            crypto::secure_array<std::byte, 32>& dest_public_key);
    //Receiver initialization
    session_state(
            crypto::secure_array<std::byte, 32>& shared_secret, crypto::DH_Keypair& self_kp);
    ~session_state() = default;
    session_state(const session_state&) = default;
    session_state(session_state&&) = default;
    session_state& operator=(session_state&&) = default;
    session_state& operator=(const session_state&) = default;

    const signal_message ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
            const crypto::secure_vector<std::byte>& aad);

    const crypto::secure_vector<std::byte> ratchet_decrypt(const signal_message& message);

    const std::optional<crypto::secure_vector<std::byte>> try_skipped_message_keys(
            const signal_message& message);

    void skip_message_keys(uint64_t until);
    void DH_ratchet(const crypto::secure_array<std::byte, 32>& remote_pub_key);

private:
    crypto::DH_Keypair self_keypair;
    crypto::secure_array<std::byte, 32> remote_public_key;
    crypto::secure_array<std::byte, 32> root_key;
    crypto::secure_array<std::byte, 32> send_chain_key;
    crypto::secure_array<std::byte, 32> receive_chain_key;
    uint64_t send_message_num = 0;
    uint64_t receive_message_num = 0;
    uint64_t previous_send_chain_size = 0;

    crypto::secure_unordered_map<std::pair<crypto::secure_array<std::byte, 32>, uint64_t>,
            crypto::secure_array<std::byte, 32>>
            skipped_keys{};
};

#endif /* end of include guard: PROTOCOL_STATE_H */
