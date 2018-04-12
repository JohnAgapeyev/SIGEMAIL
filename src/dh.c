#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "dh.h"
#include "curve25519-donna.h"
#include "keygen.h"

dh_keypair *generate_dh_keys(void) {
    dh_keypair *out = malloc(sizeof(dh_keypair));
    RAND_bytes(out->private, 32);
    sc_clamp(out->private);
    curve25519_keygen(out->public, out->private);
    return out;
}

uint8_t *generate_shared_secret(uint8_t local_private[static const 32], uint8_t remote_public[static const 32]) {
    uint8_t *shared = malloc(sizeof(uint8_t) * 32);
    curve25519_donna(shared, local_private, remote_public);
    return SHA256(shared, sizeof(uint8_t) * 32, shared);
}
