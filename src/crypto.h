#ifndef CRYPTO_H
#define CRYPTO_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <map>
#include <openssl/crypto.h>
#include <unordered_map>
#include <vector>

#include "zallocator.h"

namespace crypto {
    class DH_Keypair;

    template<typename T, std::size_t N>
    class secure_array : public std::array<T, N> {
    public:
        ~secure_array() { OPENSSL_cleanse(this->data(), this->size() * sizeof(T)); }
    };

    template<typename T>
    using secure_vector = std::vector<T, zallocator<T>>;
    template<typename T>
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;
    template<typename Key, typename T>
    using secure_map = std::map<Key, T, std::less<Key>, zallocator<std::pair<const Key, T>>>;
    template<typename Key, typename T>
    using secure_unordered_map = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>,
            zallocator<std::pair<const Key, T>>>;

    const secure_array<std::byte, 32> X3DH_sender(const DH_Keypair& local_identity,
            const DH_Keypair& local_ephemeral, const secure_array<std::byte, 32>& remote_identity,
            const secure_array<std::byte, 32>& remote_prekey,
            const secure_array<std::byte, 32>& remote_one_time_key);

    //Overload that doesn't use a one-time key
    const secure_array<std::byte, 32> X3DH_sender(const DH_Keypair& local_identity,
            const DH_Keypair& local_ephemeral, const secure_array<std::byte, 32>& remote_identity,
            const secure_array<std::byte, 32>& remote_prekey);

    const secure_array<std::byte, 32> X3DH_receiver(const DH_Keypair& local_identity,
            const DH_Keypair& local_pre_key, const DH_Keypair& local_one_time_key,
            const secure_array<std::byte, 32>& remote_identity,
            const secure_array<std::byte, 32>& remote_ephemeral);

    //Overload that doesn't use a one-time key
    const secure_array<std::byte, 32> X3DH_receiver(const DH_Keypair& local_identity,
            const DH_Keypair& local_pre_key, const secure_array<std::byte, 32>& remote_identity,
            const secure_array<std::byte, 32>& remote_ephemeral);

    const secure_array<std::byte, 64> sign_key(
            const DH_Keypair& signing_keypair, const secure_array<std::byte, 32>& key_to_sign);

    bool verify_signed_key(const secure_array<std::byte, 64>& signature,
            const secure_array<std::byte, 32>& signed_key,
            const secure_array<std::byte, 32>& public_signing_key);

    const secure_vector<std::byte> encrypt(const secure_vector<std::byte>& message,
            const secure_array<std::byte, 32>& key, const secure_vector<std::byte>& aad);
    const secure_vector<std::byte> decrypt(secure_vector<std::byte>& ciphertext,
            const secure_array<std::byte, 32>& key, const secure_vector<std::byte>& aad);

    const secure_array<std::byte, 32> root_derive(
            secure_array<std::byte, 32>& root_key, const secure_array<std::byte, 32>& dh_output);
    const secure_array<std::byte, 32> chain_derive(secure_array<std::byte, 32>& chain_key);
    const secure_array<std::byte, 32> x3dh_derive(const secure_vector<std::byte>& key_material);
} // namespace crypto

namespace std {
    template<typename T, std::size_t arr_size>
    class hash<crypto::secure_array<T, arr_size>> {
    public:
        std::size_t operator()(const crypto::secure_array<T, arr_size>& arr) const {
            std::size_t running_hash = 0;
            for (const auto& elem : arr) {
                running_hash ^= std::hash<T>{}(elem);
            }
            return running_hash;
        }
    };
    template<typename T, typename U>
    class hash<std::pair<T, U>> {
    public:
        std::size_t operator()(const std::pair<T, U>& p) const {
            return std::hash<T>{}(p.first) ^ std::hash<U>{}(p.second);
        }
    };
} // namespace std

#endif
