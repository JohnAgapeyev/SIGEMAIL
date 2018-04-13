#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "encrypt.h"

void encrypt(const uint8_t *const restrict message, const size_t mesg_len, const uint8_t key[static const restrict 32], const uint8_t *const restrict aad, const size_t aad_len, uint8_t *const restrict ciphertext, uint8_t tag[static const restrict 16]) {
    //THIS IS NOT A PROBLEM
    //Message keys are only used once in Signal, so nonce reuse is not an issue
    //See https://signal.org/docs/specifications/doubleratchet/#external-functions under the ENCRYPT function for confirmation
    static uint8_t nonce[12];
    for (int i = 0; i < 12; ++i) {
        nonce[i] = i;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);

    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, message, mesg_len);

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
}

bool decrypt(const uint8_t *const restrict ciphertext, const size_t cipher_len, const uint8_t tag[static const restrict 16], const uint8_t key[static const restrict 32], const uint8_t *const restrict aad, const size_t aad_len, uint8_t *const restrict plaintext) {
    //THIS IS NOT A PROBLEM
    //Message keys are only used once in Signal, so nonce reuse is not an issue
    //See https://signal.org/docs/specifications/doubleratchet/#external-functions under the ENCRYPT function for confirmation
    static uint8_t nonce[12];
    for (int i = 0; i < 12; ++i) {
        nonce[i] = i;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);

    int len;
    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (uint8_t *) tag)) {
        //TEMP
        abort();
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

