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
    struct secure_array : public std::array<T, N> {
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

    using shared_key = secure_array<std::byte, 32>;
    using public_key = secure_array<std::byte, 32>;
    using private_key = secure_array<std::byte, 32>;
    using signature = secure_array<std::byte, 64>;

    const shared_key X3DH_sender(const DH_Keypair& local_identity,
            const DH_Keypair& local_ephemeral, const public_key& remote_identity,
            const public_key& remote_prekey, const public_key& remote_one_time_key);

    //Overload that doesn't use a one-time key
    const shared_key X3DH_sender(const DH_Keypair& local_identity,
            const DH_Keypair& local_ephemeral, const public_key& remote_identity,
            const public_key& remote_prekey);

    const shared_key X3DH_receiver(const DH_Keypair& local_identity,
            const DH_Keypair& local_pre_key, const DH_Keypair& local_one_time_key,
            const public_key& remote_identity, const public_key& remote_ephemeral);

    //Overload that doesn't use a one-time key
    const shared_key X3DH_receiver(const DH_Keypair& local_identity,
            const DH_Keypair& local_pre_key, const public_key& remote_identity,
            const public_key& remote_ephemeral);

    const signature sign_key(const DH_Keypair& signing_keypair, const public_key& key_to_sign);

    bool verify_signed_key(const signature& signature, const public_key& signed_key,
            const public_key& public_signing_key);

    const secure_vector<std::byte> encrypt(const secure_vector<std::byte>& message,
            const shared_key& key, const secure_vector<std::byte>& aad);
    const secure_vector<std::byte> decrypt(secure_vector<std::byte>& ciphertext,
            const shared_key& key, const secure_vector<std::byte>& aad);

    const secure_array<std::byte, 32> root_derive(
            secure_array<std::byte, 32>& root_key, const secure_array<std::byte, 32>& dh_output);
    const secure_array<std::byte, 32> chain_derive(secure_array<std::byte, 32>& chain_key);
    const secure_array<std::byte, 32> x3dh_derive(const secure_vector<std::byte>& key_material);
} // namespace crypto

namespace std {
    template<typename T, std::size_t N>
    class hash<crypto::secure_array<T, N>> {
    public:
        std::size_t operator()(const crypto::secure_array<T, N>& arr) const {
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
