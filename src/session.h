#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include <cstdint>
#include <optional>

#include "crypto.h"
#include "dh.h"
#include "key_pack.h"
#include "message.h"

extern const uint64_t MAX_SKIP;

class session {
public:
    //Sender initialization
    session(crypto::shared_key& shared_secret, crypto::public_key& dest_public_key);
    //Receiver initialization
    session(crypto::shared_key& shared_secret, crypto::DH_Keypair& self_kp);
    ~session() = default;
    session(const session&) = default;
    session(session&&) = default;
    session& operator=(session&&) = default;
    session& operator=(const session&) = default;

    bool operator==(const session& other) const;
    bool operator!=(const session& other) const { return !(*this == other); }

    const signal_message ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
            const crypto::secure_vector<std::byte>& aad);

    const crypto::secure_vector<std::byte> ratchet_decrypt(const signal_message& message);

private:
    void skip_message_keys(uint64_t until);

    const std::optional<crypto::secure_vector<std::byte>> try_skipped_message_keys(
            const signal_message& message);

    void DH_ratchet(const crypto::public_key& remote_pub_key);

    crypto::DH_Keypair self_keypair;
    crypto::public_key remote_public_key;
    crypto::secure_array<std::byte, 32> root_key;
    crypto::secure_array<std::byte, 32> send_chain_key;
    crypto::secure_array<std::byte, 32> receive_chain_key;
    uint64_t send_message_num = 0;
    uint64_t receive_message_num = 0;
    uint64_t previous_send_chain_size = 0;

    crypto::secure_unordered_map<std::pair<crypto::public_key, uint64_t>, crypto::shared_key>
            skipped_keys{};
};

#endif /* end of include guard: PROTOCOL_STATE_H */
