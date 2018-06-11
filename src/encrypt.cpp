#include <cstdint>
#include <cstdlib>
#include <vector>
#include <openssl/evp.h>
#include "crypto.h"

void crypto::encrypt(const std::vector<std::byte>& message, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag) {
    //THIS IS NOT A PROBLEM
    //Message keys are only used once in Signal, so nonce reuse is not an issue
    //See https://signal.org/docs/specifications/doubleratchet/#external-functions under the ENCRYPT function for confirmation
    static uint8_t nonce[12];
    for (int i = 0; i < 12; ++i) {
        nonce[i] = i;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, reinterpret_cast<const unsigned char *>(key.data()), nonce);

    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char *>(aad.data()), aad.size());

    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &len, reinterpret_cast<const unsigned char *>(message.data()), message.size());

    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<unsigned char *>(tag.data()));

    EVP_CIPHER_CTX_free(ctx);
}

bool crypto::decrypt(const std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& plaintext) {
    //THIS IS NOT A PROBLEM
    //Message keys are only used once in Signal, so nonce reuse is not an issue
    //See https://signal.org/docs/specifications/doubleratchet/#external-functions under the ENCRYPT function for confirmation
    static uint8_t nonce[12];
    for (int i = 0; i < 12; ++i) {
        nonce[i] = i;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, reinterpret_cast<const unsigned char *>(key.data()), nonce);

    int len;
    EVP_DecryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char *>(aad.data()), aad.size());

    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(plaintext.data()), &len, reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size());

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, reinterpret_cast<unsigned char *>(tag.data()))) {
        //TEMP
        abort();
    }

    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(plaintext.data()) + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

