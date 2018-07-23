#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <optional>
#include "crypto.h"
#include "protocol_state.h"
#include "message.h"

extern const uint64_t MAX_SKIP;

const signal_message ratchet_encrypt(session_state& state, const crypto::secure_vector<std::byte>& plaintext, const crypto::secure_vector<std::byte>& aad);
const crypto::secure_vector<std::byte> ratchet_decrypt(session_state& state, const signal_message& message);
const std::optional<crypto::secure_vector<std::byte>> try_skipped_message_keys(session_state& state, const signal_message& message);
void skip_message_keys(session_state& state, uint64_t until);
void DH_ratchet(session_state& state, const crypto::secure_array<std::byte, 32>& remote_public_key);

#endif /* end of include guard: PROTOCOL_H */
