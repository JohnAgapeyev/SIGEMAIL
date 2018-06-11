#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <cstdlib>
#include <array>
#include <cstddef>
#include <vector>

namespace crypto {
    class DH_Keypair;

    void encrypt(const std::vector<std::byte>& message, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag);
    bool decrypt(const std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& plaintext);

    std::array<std::byte, 32> root_derive(std::array<std::byte, 32>& root_key, const std::array<std::byte, 32>& dh_output);
    std::array<std::byte, 32> chain_derive(std::array<std::byte, 32>& chain_key);
}

#endif
