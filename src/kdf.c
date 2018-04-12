#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "kdf.h"

#define KDF_COUNT 10000

void root_derive(uint8_t root_key[static const 32], uint8_t dh_output[static const 32], uint8_t out_root[static 32], uint8_t out_chain[static 32]) {
    uint8_t temp[64];
    PKCS5_PBKDF2_HMAC((const char *const) dh_output, sizeof(uint8_t) * 32, root_key, sizeof(uint8_t) * 32, KDF_COUNT, EVP_sha512(), 64, temp);

    //Write key halves into out parameters
    memcpy(out_root, temp, 32);
    memcpy(out_chain, temp + 32, 32);
}

void chain_derive(uint8_t chain_key[static const 32], uint8_t out_chain[static 32], uint8_t out_message[static 32]) {
    PKCS5_PBKDF2_HMAC((const char *const) chain_key, sizeof(uint8_t) * 32, &(uint8_t){0x01}, 1, KDF_COUNT, EVP_sha512(), 32, out_chain);
    PKCS5_PBKDF2_HMAC((const char *const) chain_key, sizeof(uint8_t) * 32, &(uint8_t){0x02}, 1, KDF_COUNT, EVP_sha512(), 32, out_message);
}

