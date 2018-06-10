#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include "crypto.h"

#define KDF_COUNT 10000

void crypto::root_derive(std::array<std::byte, 32> root_key, std::array<std::byte, 32> dh_output, std::array<std::byte, 32> out_root, std::array<std::byte, 32> out_chain) {
    uint8_t temp[64];
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(dh_output.data()), sizeof(uint8_t) * 32, reinterpret_cast<unsigned char *>(root_key.data()), sizeof(uint8_t) * 32, KDF_COUNT, EVP_sha512(), 64, temp);

    //Write key halves into out parameters
    memcpy(out_root.data(), temp, 32);
    memcpy(out_chain.data(), temp + 32, 32);
}

void crypto::chain_derive(std::array<std::byte, 32> chain_key, std::array<std::byte, 32> out_chain, std::array<std::byte, 32> out_message) {
    const unsigned char in_1 = 0x01;
    const unsigned char in_2 = 0x01;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(uint8_t) * 32, &in_1, 1, KDF_COUNT, EVP_sha512(), 32, reinterpret_cast<unsigned char *>(out_chain.data()));
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(uint8_t) * 32, &in_2, 1, KDF_COUNT, EVP_sha512(), 32, reinterpret_cast<unsigned char *>(out_message.data()));
}

