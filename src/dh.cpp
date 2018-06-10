#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "dh.h"
#include "curve25519-donna.h"
#include "keygen.h"

DH_Keypair::DH_Keypair() {
    RAND_bytes(reinterpret_cast<unsigned char *>(private_key.data()), 32);
    sc_clamp(reinterpret_cast<unsigned char *>(private_key.data()));
    curve25519_keygen(reinterpret_cast<unsigned char *>(public_key.data()), reinterpret_cast<unsigned char *>(private_key.data()));
}

std::array<std::byte, 32> DH_Keypair::generate_shared_secret(const std::array<std::byte, 32>& remote_public) const noexcept {
    std::array<std::byte, 32> out;
    curve25519_donna(reinterpret_cast<unsigned char *>(out.data()), reinterpret_cast<const unsigned char *>(private_key.data()), reinterpret_cast<const unsigned char *>(remote_public.data()));
    SHA256(reinterpret_cast<unsigned char *>(out.data()), sizeof(uint8_t) * 32, reinterpret_cast<unsigned char *>(out.data()));
    return out;
}
