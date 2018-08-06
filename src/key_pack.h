#ifndef KEY_PACK_H
#define KEY_PACK_H

#include "crypto.h"
#include "dh.h"

class initial_key_pack {
public:
    initial_key_pack(const crypto::DH_Keypair& signing_keys,
            const crypto::secure_array<std::byte, 32>& pre_key,
            const crypto::secure_vector<crypto::secure_array<std::byte, 32>>& one_time_keys);
    ~initial_key_pack() = default;
    initial_key_pack(const initial_key_pack&) = default;
    initial_key_pack(initial_key_pack&&) = default;
    initial_key_pack& operator=(initial_key_pack&&) = default;
    initial_key_pack& operator=(const initial_key_pack&) = default;

private:
    crypto::secure_array<std::byte, 32> identity_public_key;
    crypto::secure_array<std::byte, 32> signed_pre_key;
    crypto::secure_array<std::byte, 64> pre_key_signature;
    crypto::secure_vector<crypto::secure_array<std::byte, 32>> one_time_pre_keys;
};

class pre_key_update {
public:
    pre_key_update(const crypto::DH_Keypair& signing_keys,
            const crypto::secure_array<std::byte, 32>& pre_key);
    ~pre_key_update() = default;
    pre_key_update(const pre_key_update&) = default;
    pre_key_update(pre_key_update&&) = default;
    pre_key_update& operator=(pre_key_update&&) = default;
    pre_key_update& operator=(const pre_key_update&) = default;

private:
    crypto::secure_array<std::byte, 32> signed_pre_key;
    crypto::secure_array<std::byte, 64> pre_key_signature;
};

#endif /* end of include guard: KEY_PACK_H */
