#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <cstdlib>
#include <array>
#include <cstddef>

namespace crypto {
    class DH_Keypair;

    void encrypt(const uint8_t *const message, const size_t mesg_len, const uint8_t key[], const uint8_t *const aad, const size_t aad_len, uint8_t *const ciphertext, uint8_t tag[]);
    bool decrypt(const uint8_t *const ciphertext, const size_t cipher_len, const uint8_t tag[], const uint8_t key[], const uint8_t *const aad, const size_t aad_len, uint8_t *const plaintext);

    void root_derive(std::array<std::byte, 32> root_key, std::array<std::byte, 32> dh_output, std::array<std::byte, 32> out_root, std::array<std::byte, 32> out_chain);
    void chain_derive(std::array<std::byte, 32> chain_key, std::array<std::byte, 32> out_chain, std::array<std::byte, 32> out_message);
}

#endif
