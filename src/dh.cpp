#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "dh.h"
#include "curve25519-donna.h"
#include "keygen.h"

dh_keypair *generate_dh_keys(void) {
    dh_keypair *out = (dh_keypair *) malloc(sizeof(dh_keypair));
    RAND_bytes(reinterpret_cast<unsigned char *>(out->private_key.data()), 32);
    sc_clamp(reinterpret_cast<unsigned char *>(out->private_key.data()));
    curve25519_keygen(reinterpret_cast<unsigned char *>(out->public_key.data()), reinterpret_cast<unsigned char *>(out->private_key.data()));
    return out;
}

uint8_t *generate_shared_secret(std::array<std::byte, 32> local_private, std::array<std::byte, 32> remote_public) {
    uint8_t *shared = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    curve25519_donna(shared, reinterpret_cast<unsigned char *>(local_private.data()), reinterpret_cast<unsigned char *>(remote_public.data()));
    return SHA256(shared, sizeof(uint8_t) * 32, shared);
}
