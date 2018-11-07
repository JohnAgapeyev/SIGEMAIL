#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/sha.h>
extern "C" {
#include "curve25519-donna.h"
#include "keygen.h"
}
#include "crypto.h"
#include "dh.h"

using namespace crypto;

crypto::DH_Keypair::DH_Keypair() {
    RAND_bytes(reinterpret_cast<unsigned char*>(private_key.data()), 32);
    sc_clamp(reinterpret_cast<unsigned char*>(private_key.data()));
    curve25519_keygen(reinterpret_cast<unsigned char*>(public_key.data()),
            reinterpret_cast<unsigned char*>(private_key.data()));
}

const crypto::shared_key crypto::DH_Keypair::generate_shared_secret(
        const crypto::public_key& remote_public) const noexcept {
    secure_array<std::byte, 32> out;
    curve25519_donna(reinterpret_cast<unsigned char*>(out.data()),
            reinterpret_cast<const unsigned char*>(private_key.data()),
            reinterpret_cast<const unsigned char*>(remote_public.data()));
    SHA256(reinterpret_cast<unsigned char*>(out.data()), sizeof(uint8_t) * 32,
            reinterpret_cast<unsigned char*>(out.data()));
    return out;
}

const crypto::shared_key crypto::X3DH_sender(const crypto::DH_Keypair& local_identity,
        const crypto::DH_Keypair& local_ephemeral,
        const crypto::public_key& remote_identity,
        const crypto::public_key& remote_prekey,
        const crypto::public_key& remote_one_time_key) {
    const auto dh1 = local_identity.generate_shared_secret(remote_prekey);
    const auto dh2 = local_ephemeral.generate_shared_secret(remote_identity);
    const auto dh3 = local_ephemeral.generate_shared_secret(remote_prekey);
    const auto dh4 = local_ephemeral.generate_shared_secret(remote_one_time_key);

    secure_vector<std::byte> kdf_input;

    //Fill the kdf input
    kdf_input.insert(kdf_input.end(), dh1.begin(), dh1.end());
    kdf_input.insert(kdf_input.end(), dh2.begin(), dh2.end());
    kdf_input.insert(kdf_input.end(), dh3.begin(), dh3.end());
    kdf_input.insert(kdf_input.end(), dh4.begin(), dh4.end());

    return x3dh_derive(kdf_input);
}

const crypto::shared_key crypto::X3DH_receiver(const DH_Keypair& local_identity,
        const DH_Keypair& local_pre_key, const DH_Keypair& local_one_time_key,
        const crypto::public_key& remote_identity,
        const crypto::public_key& remote_ephemeral) {
    const auto dh1 = local_pre_key.generate_shared_secret(remote_identity);
    const auto dh2 = local_identity.generate_shared_secret(remote_ephemeral);
    const auto dh3 = local_pre_key.generate_shared_secret(remote_ephemeral);
    const auto dh4 = local_one_time_key.generate_shared_secret(remote_ephemeral);

    secure_vector<std::byte> kdf_input;

    //Fill the kdf input
    kdf_input.insert(kdf_input.end(), dh1.begin(), dh1.end());
    kdf_input.insert(kdf_input.end(), dh2.begin(), dh2.end());
    kdf_input.insert(kdf_input.end(), dh3.begin(), dh3.end());
    kdf_input.insert(kdf_input.end(), dh4.begin(), dh4.end());

    return x3dh_derive(kdf_input);
}

const crypto::shared_key crypto::X3DH_sender(const crypto::DH_Keypair& local_identity,
        const crypto::DH_Keypair& local_ephemeral,
        const crypto::public_key& remote_identity,
        const crypto::public_key& remote_prekey) {
    const auto dh1 = local_identity.generate_shared_secret(remote_prekey);
    const auto dh2 = local_ephemeral.generate_shared_secret(remote_identity);
    const auto dh3 = local_ephemeral.generate_shared_secret(remote_prekey);

    secure_vector<std::byte> kdf_input;

    //Fill the kdf input
    kdf_input.insert(kdf_input.end(), dh1.begin(), dh1.end());
    kdf_input.insert(kdf_input.end(), dh2.begin(), dh2.end());
    kdf_input.insert(kdf_input.end(), dh3.begin(), dh3.end());

    return x3dh_derive(kdf_input);
}

const crypto::shared_key crypto::X3DH_receiver(const DH_Keypair& local_identity,
        const DH_Keypair& local_pre_key, const crypto::public_key& remote_identity,
        const crypto::public_key& remote_ephemeral) {
    const auto dh1 = local_pre_key.generate_shared_secret(remote_identity);
    const auto dh2 = local_identity.generate_shared_secret(remote_ephemeral);
    const auto dh3 = local_pre_key.generate_shared_secret(remote_ephemeral);

    secure_vector<std::byte> kdf_input;

    //Fill the kdf input
    kdf_input.insert(kdf_input.end(), dh1.begin(), dh1.end());
    kdf_input.insert(kdf_input.end(), dh2.begin(), dh2.end());
    kdf_input.insert(kdf_input.end(), dh3.begin(), dh3.end());

    return x3dh_derive(kdf_input);
}
