#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "kdf.h"

#define KDF_COUNT 10000

void root_derive(uint8_t root_key[], uint8_t dh_output[], uint8_t out_root[], uint8_t out_chain[]) {
    uint8_t temp[64];
    PKCS5_PBKDF2_HMAC((const char *const) dh_output, sizeof(uint8_t) * 32, root_key, sizeof(uint8_t) * 32, KDF_COUNT, EVP_sha512(), 64, temp);

    //Write key halves into out parameters
    memcpy(out_root, temp, 32);
    memcpy(out_chain, temp + 32, 32);
}

void chain_derive(uint8_t chain_key[], uint8_t out_chain[], uint8_t out_message[]) {
    const unsigned char in_1 = 0x01;
    const unsigned char in_2 = 0x01;
    PKCS5_PBKDF2_HMAC((const char *const) chain_key, sizeof(uint8_t) * 32, &in_1, 1, KDF_COUNT, EVP_sha512(), 32, out_chain);
    PKCS5_PBKDF2_HMAC((const char *const) chain_key, sizeof(uint8_t) * 32, &in_2, 1, KDF_COUNT, EVP_sha512(), 32, out_message);
}

