#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/bn.h>
#include "signature.h"

struct xeddsa_signature * xeddsa_sign(unsigned char mont_priv[crypto_kx_SECRETKEYBYTES], unsigned char *mesg, size_t len, unsigned char rand_data[64]) {
    return NULL;
}

bool xeddsa_verify(unsigned char mont_pub[crypto_kx_PUBLICKEYBYTES], unsigned char *mesg, size_t len, struct xeddsa_signature *sig) {
    return false;
}

struct vxeddsa_signature * vxeddsa_sign(unsigned char mont_priv[crypto_kx_SECRETKEYBYTES], unsigned char *mesg, size_t len, unsigned char rand_data[64]) {
    return NULL;
}

unsigned char * vxeddsa_verify(unsigned char mont_pub[crypto_kx_PUBLICKEYBYTES], unsigned char *mesg, size_t len, struct vxeddsa_signature *sig) {
    return NULL;
}

