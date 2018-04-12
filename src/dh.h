#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <stdint.h>

typedef struct {
    uint8_t private[32];
    uint8_t public[32];
} dh_keypair;

dh_keypair *generate_dh_keys(void);
uint8_t *generate_shared_secret(uint8_t local_private[static const 32], uint8_t remote_public[static const 32]);


#endif
