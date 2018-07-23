#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include "crypto.h"

#define KDF_COUNT 10000

using namespace crypto;

const secure_array<std::byte, 32> crypto::root_derive(secure_array<std::byte, 32>& root_key, const secure_array<std::byte, 32>& dh_output) {
    secure_array<std::byte, 64> temp;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(dh_output.data()), sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(root_key.data()),
            sizeof(std::byte) * 32, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 64, reinterpret_cast<unsigned char *>(temp.data()));

    secure_array<std::byte, 32> chain_key;

    //Write key halves into out parameters
    memcpy(root_key.data(), temp.data(), 32);
    memcpy(chain_key.data(), temp.data() + 32, 32);

    return chain_key;
}

const secure_array<std::byte, 32> crypto::chain_derive(secure_array<std::byte, 32>& chain_key) {
    const unsigned char in_1 = 0x01;
    const unsigned char in_2 = 0x01;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(std::byte) * 32, &in_1, 1, KDF_COUNT, EVP_sha512(),
            sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(chain_key.data()));

    secure_array<std::byte, 32> message_key;
    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(chain_key.data()), sizeof(std::byte) * 32, &in_2, 1, KDF_COUNT, EVP_sha512(),
            sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(message_key.data()));

    return message_key;
}

const secure_array<std::byte, 32> crypto::x3dh_derive(const secure_vector<std::byte>& key_material) {
    //Pad with 32 bytes of 0xFF
    secure_vector<std::byte> kdf_input{32, std::byte{0xFF}};

    //Add the key material
    kdf_input.insert(kdf_input.end(), key_material.begin(), key_material.end());

    //Fill with a sha512 worth of zeroes
    secure_array<std::byte, 64> kdf_salt({std::byte{0}});

    secure_array<std::byte, 32> kdf_output;

    PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(kdf_input.data()), kdf_input.size(), reinterpret_cast<const unsigned char *>(kdf_salt.data()),
            kdf_salt.size(), KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 32, reinterpret_cast<unsigned char *>(kdf_output.data()));

    return kdf_output;
}
