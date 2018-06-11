#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include "crypto.h"

#define KDF_COUNT 10000

std::array<std::byte, 32> crypto::root_derive(std::array<std::byte, 32>& root_key, const std::array<std::byte, 32>& dh_output) {
    std::array<std::byte, 64> temp;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(dh_output.data()), sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(root_key.data()), sizeof(std::byte) * 32, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 64, reinterpret_cast<unsigned char *>(temp.data()));

    std::array<std::byte, 32> chain_key;

    //Write key halves into out parameters
    memcpy(root_key.data(), temp.data(), 32);
    memcpy(chain_key.data(), temp.data() + 32, 32);

    return chain_key;
}

std::array<std::byte, 32> crypto::chain_derive(std::array<std::byte, 32>& chain_key) {
    const unsigned char in_1 = 0x01;
    const unsigned char in_2 = 0x01;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(std::byte) * 32, &in_1, 1, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(chain_key.data()));

    std::array<std::byte, 32> message_key;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(std::byte) * 32, &in_2, 1, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(message_key.data()));

    return message_key;
}

