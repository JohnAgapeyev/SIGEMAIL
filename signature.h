#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <stdbool.h>
#include <sodium.h>

struct xeddsa_signature {
    unsigned char R[32];
    unsigned char s[32];
};

struct vxeddsa_signature {
    unsigned char V[32];
    unsigned char h[32];
    unsigned char s[32];
};

struct xeddsa_signature * xeddsa_sign(unsigned char mont_priv[crypto_kx_SECRETKEYBYTES], unsigned char *mesg, size_t len, unsigned char rand_data[64]);
bool xeddsa_verify(unsigned char mont_pub[crypto_kx_PUBLICKEYBYTES], unsigned char *mesg, size_t len, struct xeddsa_signature *sig);

struct vxeddsa_signature * vxeddsa_sign(unsigned char mont_priv[crypto_kx_SECRETKEYBYTES], unsigned char *mesg, size_t len, unsigned char rand_data[64]);
unsigned char * vxeddsa_verify(unsigned char mont_pub[crypto_kx_PUBLICKEYBYTES], unsigned char *mesg, size_t len, struct vxeddsa_signature *sig);

#endif
