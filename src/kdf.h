#ifndef KDF_H
#define KDF_H

#include <stdint.h>

void root_derive(uint8_t root_key[], uint8_t dh_output[], uint8_t out_root[], uint8_t out_chain[]);
void chain_derive(uint8_t chain_key[], uint8_t out_chain[], uint8_t out_message[]);

#endif
