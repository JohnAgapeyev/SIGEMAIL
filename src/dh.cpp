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
    RAND_bytes(out->private_key, 32);
    sc_clamp(out->private_key);
    curve25519_keygen(out->public_key, out->private_key);
    return out;
}

uint8_t *generate_shared_secret(uint8_t local_private_key[], uint8_t remote_public_key[]) {
    uint8_t *shared = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    curve25519_donna(shared, local_private_key, remote_public_key);
    return SHA256(shared, sizeof(uint8_t) * 32, shared);
}
