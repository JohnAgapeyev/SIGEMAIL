#include <cstdint>
#include <cstring>
#include <openssl/evp.h>

#include "crypto.h"
#include "error.h"

#define KDF_COUNT 30000

const crypto::shared_key crypto::root_derive(
        crypto::shared_key& root_key, const crypto::shared_key& dh_output) {
    secure_array<std::byte, 64> temp;
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(dh_output.data()), sizeof(std::byte) * 32,
                reinterpret_cast<unsigned char*>(root_key.data()), sizeof(std::byte) * 32,
                KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 64,
                reinterpret_cast<unsigned char*>(temp.data()))) {
        throw crypto::openssl_error(ERR_get_error());
    }

    crypto::shared_key chain_key;

    //Write key halves into out parameters
    memcpy(root_key.data(), temp.data(), 32);
    memcpy(chain_key.data(), temp.data() + 32, 32);

    return chain_key;
}

const crypto::shared_key crypto::chain_derive(crypto::shared_key& chain_key) {
    const unsigned char in_1 = 0x01;
    const unsigned char in_2 = 0x01;
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(chain_key.data()), sizeof(std::byte) * 32,
                &in_1, 1, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 32,
                reinterpret_cast<unsigned char*>(chain_key.data()))) {
        throw crypto::openssl_error(ERR_get_error());
    }

    crypto::shared_key message_key;
    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(chain_key.data()), sizeof(std::byte) * 32,
                &in_2, 1, KDF_COUNT, EVP_sha512(), sizeof(std::byte) * 32,
                reinterpret_cast<unsigned char*>(message_key.data()))) {
        throw crypto::openssl_error(ERR_get_error());
    }

    return message_key;
}

const crypto::shared_key crypto::x3dh_derive(const secure_vector<std::byte>& key_material) {
    //Pad with 32 bytes of 0xFF
    crypto::secure_vector<std::byte> kdf_input{32, std::byte{0xFF}};

    //Add the key material
    kdf_input.insert(kdf_input.end(), key_material.begin(), key_material.end());

    //Fill with a sha512 worth of zeroes
    crypto::secure_array<std::byte, 64> kdf_salt{{std::byte{0}}};

    crypto::shared_key kdf_output;

    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(kdf_input.data()), kdf_input.size(),
                reinterpret_cast<const unsigned char*>(kdf_salt.data()), kdf_salt.size(), KDF_COUNT,
                EVP_sha512(), sizeof(std::byte) * 32,
                reinterpret_cast<unsigned char*>(kdf_output.data()))) {
        throw crypto::openssl_error(ERR_get_error());
    }

    return kdf_output;
}

const crypto::shared_key crypto::password_derive(const crypto::secure_string& password) {
    const unsigned char salt = 0xab;

    crypto::shared_key derived_key;

    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()),
                sizeof(std::byte) * password.size(), &salt, 1, KDF_COUNT, EVP_sha512(),
                sizeof(std::byte) * 32, reinterpret_cast<unsigned char*>(derived_key.data()))) {
        throw crypto::openssl_error(ERR_get_error());
    }

    return derived_key;
}
