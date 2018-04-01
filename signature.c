#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/bn.h>
#include "signature.h"

struct edwards_key_pair {
    BIGNUM *private;
    BIGNUM *public;
};

static BIGNUM * convert_mont(BIGNUM *u);
static BIGNUM * u_to_y(BIGNUM *u);
static struct edwards_key_pair * calculate_key_pair(BIGNUM *u);
static unsigned char * hash_i(int i, unsigned char *mesg, size_t len);
static BIGNUM * elligator2(BIGNUM *r);
static BIGNUM * hash_to_point(unsigned char *mesg, size_t len);

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

BIGNUM * convert_mont(BIGNUM *u) {
    return NULL;
}

BIGNUM * u_to_y(BIGNUM *u) {
    return NULL;
}

struct edwards_key_pair * calculate_key_pair(BIGNUM *u) {
    return NULL;
}

unsigned char * hash_i(int i, unsigned char *mesg, size_t len) {
    return NULL;
}

BIGNUM * elligator2(BIGNUM *r) {
    return NULL;
}

BIGNUM * hash_to_point(unsigned char *mesg, size_t len) {
    return NULL;
}
