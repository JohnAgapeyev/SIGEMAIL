#include <cstdint>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

#include "crypto.h"

const crypto::secure_vector<std::byte> crypto::encrypt(const secure_vector<std::byte>& message,
        const crypto::shared_key& key, const secure_vector<std::byte>& aad) {
    std::array<std::byte, 12> nonce;
    RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(nonce.data()));

    int len;
    EVP_EncryptUpdate(
            ctx, NULL, &len, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());

    secure_vector<std::byte> ciphertext;
    ciphertext.resize(message.size());

    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
            reinterpret_cast<const unsigned char*>(message.data()), message.size());

    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &len);

    secure_vector<std::byte> tag;
    tag.resize(16);

    EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<unsigned char*>(tag.data()));

    //Insert the tag at the end of the ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    //Insert nonce at the beginning
    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

const crypto::secure_vector<std::byte> crypto::decrypt(secure_vector<std::byte>& ciphertext,
        const crypto::shared_key& key, const secure_vector<std::byte>& aad) {
    if (ciphertext.size() <= 28) {
        throw std::runtime_error("Received message was too short to decrypt");
    }

    std::array<std::byte, 12> nonce;
    for (int i = 0; i < 12; ++i) {
        nonce[i] = ciphertext[i];
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(nonce.data()));

    int len;
    EVP_DecryptUpdate(
            ctx, NULL, &len, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());

    secure_vector<std::byte> plaintext;
    plaintext.resize(ciphertext.size() - 28);

    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
            reinterpret_cast<const unsigned char*>(ciphertext.data() + 12), ciphertext.size() - 28);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                reinterpret_cast<unsigned char*>(ciphertext.data() + ciphertext.size() - 16))) {
        throw std::runtime_error("Message tag failed to enter correctly");
    }

    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len)) {
        throw std::runtime_error("Message failed to decrypt");
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
