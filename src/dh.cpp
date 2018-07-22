#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "curve25519-donna.h"
#include "keygen.h"
#include "dh.h"
#include "crypto.h"

using namespace crypto;

crypto::DH_Keypair::DH_Keypair() {
    RAND_bytes(reinterpret_cast<unsigned char *>(private_key.data()), 32);
    sc_clamp(reinterpret_cast<unsigned char *>(private_key.data()));
    curve25519_keygen(reinterpret_cast<unsigned char *>(public_key.data()), reinterpret_cast<unsigned char *>(private_key.data()));
}

const secure_array<std::byte, 32> crypto::DH_Keypair::generate_shared_secret(const secure_array<std::byte, 32>& remote_public) const noexcept {
    secure_array<std::byte, 32> out;
    curve25519_donna(reinterpret_cast<unsigned char *>(out.data()), reinterpret_cast<const unsigned char *>(private_key.data()), reinterpret_cast<const unsigned char *>(remote_public.data()));
    SHA256(reinterpret_cast<unsigned char *>(out.data()), sizeof(uint8_t) * 32, reinterpret_cast<unsigned char *>(out.data()));
    return out;
}

const secure_array<std::byte, 32> crypto::X3DH(const crypto::DH_Keypair& local_identity, const crypto::DH_Keypair& local_ephemeral,
        const secure_array<std::byte, 32>& remote_identity, const secure_array<std::byte, 32>& remote_prekey,
        const secure_array<std::byte, 32>& remote_one_time_key) {

    auto dh1 = local_identity.generate_shared_secret(remote_prekey);
    auto dh2 = local_ephemeral.generate_shared_secret(remote_identity);
    auto dh3 = local_ephemeral.generate_shared_secret(remote_prekey);
    auto dh4 = local_ephemeral.generate_shared_secret(remote_one_time_key);

    secure_vector<std::byte> kdf_input;

    //Fill the kdf input
    kdf_input.insert(kdf_input.end(), dh1.begin(), dh1.end());
    kdf_input.insert(kdf_input.end(), dh2.begin(), dh2.end());
    kdf_input.insert(kdf_input.end(), dh3.begin(), dh3.end());
    kdf_input.insert(kdf_input.end(), dh4.begin(), dh4.end());

    return x3dh_derive(kdf_input);
}
