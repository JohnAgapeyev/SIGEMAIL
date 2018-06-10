#include <cstdint>
#include <cstdlib>
#include <openssl/evp.h>
#include "crypto.h"

void crypto::encrypt(const uint8_t *const  message, const size_t mesg_len, const uint8_t key[], const uint8_t *const  aad, const size_t aad_len, uint8_t *const  ciphertext, uint8_t tag[]) {
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

bool crypto::decrypt(const uint8_t *const  ciphertext, const size_t cipher_len, const uint8_t tag[], const uint8_t key[], const uint8_t *const  aad, const size_t aad_len, uint8_t *const  plaintext) {
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

