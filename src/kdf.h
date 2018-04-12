#ifndef KDF_H
#define KDF_H

#include <stdint.h>

void root_derive(uint8_t root_key[static const 32], uint8_t dh_output[static const 32], uint8_t out_root[static 32], uint8_t out_chain[static 32]);
void chain_derive(uint8_t chain_key[static const 32], uint8_t out_chain[static 32], uint8_t out_message[static 32]);

#endif
