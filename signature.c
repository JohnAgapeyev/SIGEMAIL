#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include <openssl/bn.h>
#include "signature.h"

#define CURVE_25519_N 2
#define CURVE_25519_C 8
#define CURVE_25519_A 486662
#define CURVE_25519_B 256
#define CURVE_25519_ORDER_P 255
#define CURVE_25519_ORDER_Q 253

static BIGNUM * get_curve25519_p(void);
static BIGNUM * get_curve25519_q(void);
static BIGNUM * get_curve25519_d(void);

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
    BN_CTX *ctx = BN_CTX_new();

    //power == 2^255
    BIGNUM *power = BN_new();
    BN_one(power);
    BN_lshift(power, power, 255);

    //u_masked = u mod 2^255
    BIGNUM *u_masked = BN_dup(u);
    BN_nnmod(u_masked, u_masked, power, ctx);

    BIGNUM *converted = u_to_y(u_masked);

    BN_clear_bit(converted, 255);

    BN_CTX_free(ctx);
    BN_free(u_masked);
    BN_free(power);

    return converted;
}

BIGNUM * u_to_y(BIGNUM *u) {
    BIGNUM *p = get_curve25519_p();

    BIGNUM *minus = BN_dup(u);
    BIGNUM *inverse = BN_dup(u);

    BN_sub(minus, minus, BN_value_one());

    BN_add(inverse, inverse, BN_value_one());

    BN_CTX *ctx = BN_CTX_new();

    BN_mod_inverse(inverse, inverse, p, ctx);

    BN_mod_mul(inverse, minus, inverse, p, ctx);

    BN_free(p);
    BN_free(minus);
    BN_CTX_free(ctx);

    return inverse;
}

struct edwards_key_pair * calculate_key_pair(BIGNUM *u) {
    unsigned char multiple[crypto_scalarmult_ed25519_BYTES];




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

BIGNUM * get_curve25519_p(void) {
    BIGNUM *nineteen = BN_new();
    BN_set_word(nineteen, 19);

    BIGNUM *power = BN_new();
    BN_one(power);
    BN_lshift(power, power, 255);

    BN_sub(power, power, nineteen);

    BN_free(nineteen);

    return power;
}

BIGNUM * get_curve25519_q(void) {
    BIGNUM *power = BN_new();
    BN_one(power);
    BN_lshift(power, power, 252);

    BIGNUM *add = NULL;

    BN_dec2bn(&add, "27742317777372353535851937790883648493");

    BN_add(power, power, add);

    BN_free(add);

    return power;
}

BIGNUM * get_curve25519_d(void) {
    BIGNUM *p = get_curve25519_p();

    BIGNUM *num = BN_new();
    BIGNUM *denom = BN_new();

    BN_set_word(num, -121665);
    BN_set_word(denom, 121666);

    BN_CTX *ctx = BN_CTX_new();

    BN_div(num, NULL, num, denom, ctx);

    BN_nnmod(num, num, p, ctx);

    BN_free(p);
    BN_free(denom);
    BN_CTX_free(ctx);

    return num;
}

