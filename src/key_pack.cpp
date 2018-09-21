#include "crypto.h"
#include "dh.h"
#include "key_pack.h"

initial_key_pack::initial_key_pack(const crypto::DH_Keypair& signing_keys,
        const crypto::secure_array<std::byte, 32>& pre_key,
        const crypto::secure_vector<crypto::DH_Keypair>& one_time_keys) :
        identity_public_key(signing_keys.get_public()),
        signed_pre_key(pre_key), pre_key_signature(crypto::sign_key(signing_keys, pre_key)),
        one_time_pre_keys(one_time_keys) {}

pre_key_update::pre_key_update(const crypto::DH_Keypair& signing_keys,
        const crypto::secure_array<std::byte, 32>& pre_key) :
        signed_pre_key(pre_key),
        pre_key_signature(crypto::sign_key(signing_keys, pre_key)) {}

