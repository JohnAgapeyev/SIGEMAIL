#include <cstdint>
#include <cstdlib>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

#include "crypto.h"

const crypto::secure_vector<std::byte> crypto::encrypt(const secure_vector<std::byte>& message,
        const crypto::shared_key& key, const secure_vector<std::byte>& aad) {
    std::array<std::byte, 12> nonce;
    RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), 12);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{
            EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
    if (!ctx) {
        throw std::bad_alloc();
    }

    if (!EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), NULL,
                reinterpret_cast<const unsigned char*>(key.data()),
                reinterpret_cast<const unsigned char*>(nonce.data()))) {
        throw std::runtime_error("EVP_EncryptInit_ex");
    }

    int len;
    if (!EVP_EncryptUpdate(ctx.get(), NULL, &len,
                reinterpret_cast<const unsigned char*>(aad.data()), aad.size())) {
        throw std::domain_error("EVP_EncryptUpdate");
    }

    secure_vector<std::byte> ciphertext;
    ciphertext.resize(message.size());

    if (!EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                reinterpret_cast<const unsigned char*>(message.data()), message.size())) {
        throw std::domain_error("EVP_EncryptUpdate");
    }

    if (!EVP_EncryptFinal_ex(
                ctx.get(), reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &len)) {
        throw std::domain_error("EVP_EncryptFinal_ex");
    }

    secure_vector<std::byte> tag;
    tag.resize(16);

    EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<unsigned char*>(tag.data()));

    //Insert the tag at the end of the ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    //Insert nonce at the beginning
    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());

    return ciphertext;
}

const crypto::secure_vector<std::byte> crypto::decrypt(secure_vector<std::byte>& ciphertext,
        const crypto::shared_key& key, const secure_vector<std::byte>& aad) {
    if (ciphertext.size() <= 28) {
        throw std::invalid_argument("Received message was too short to decrypt");
    }

    std::array<std::byte, 12> nonce;
    for (int i = 0; i < 12; ++i) {
        nonce[i] = ciphertext[i];
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{
            EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
    if (!ctx) {
        throw std::bad_alloc();
    }

    if (!EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), NULL,
                reinterpret_cast<const unsigned char*>(key.data()),
                reinterpret_cast<const unsigned char*>(nonce.data()))) {
        throw std::domain_error("EVP_DecryptInit_ex");
    }

    int len;
    if (!EVP_DecryptUpdate(ctx.get(), NULL, &len,
                reinterpret_cast<const unsigned char*>(aad.data()), aad.size())) {
        throw std::domain_error("EVP_DecryptUpdate");
    }

    secure_vector<std::byte> plaintext;
    plaintext.resize(ciphertext.size() - 28);

    if (!EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                reinterpret_cast<const unsigned char*>(ciphertext.data() + 12),
                ciphertext.size() - 28)) {
        throw std::domain_error("EVP_DecryptUpdate");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                reinterpret_cast<unsigned char*>(ciphertext.data() + ciphertext.size() - 16))) {
        throw std::invalid_argument("Message tag failed to enter correctly");
    }

    if (!EVP_DecryptFinal_ex(
                ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len)) {
        throw std::runtime_error("Message failed to decrypt");
    }

    return plaintext;
}
