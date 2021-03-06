#include <array>
#include <openssl/rand.h>
#include <utility>

#include "crypto.h"
#include "dh.h"
extern "C" {
#include "xeddsa.h"
}

const crypto::signature crypto::sign_key(
        const crypto::DH_Keypair& signing_keypair, const crypto::public_key& key_to_sign) {
    secure_array<std::byte, 64> random_input;
    RAND_bytes(reinterpret_cast<unsigned char*>(random_input.data()), 64);

    secure_array<std::byte, 64> output_signature;

    if (xed25519_sign(reinterpret_cast<unsigned char*>(output_signature.data()),
                reinterpret_cast<const unsigned char*>(signing_keypair.private_key.data()),
                reinterpret_cast<const unsigned char*>(key_to_sign.data()), key_to_sign.size(),
                reinterpret_cast<const unsigned char*>(random_input.data()))) {
        //Signature failed
        throw std::runtime_error("Key signing failed");
    }

    return output_signature;
}

[[nodiscard]] bool crypto::verify_signed_key(const crypto::signature& signature,
        const crypto::public_key& signed_key, const crypto::public_key& public_signing_key) {
    return !xed25519_verify(reinterpret_cast<const unsigned char*>(signature.data()),
            reinterpret_cast<const unsigned char*>(public_signing_key.data()),
            reinterpret_cast<const unsigned char*>(signed_key.data()), signed_key.size());
}
