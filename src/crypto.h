#ifndef CRYPTO_H
#define CRYPTO_H

#include <boost/algorithm/string.hpp>
#include <boost/container_hash/hash.hpp>
#include <boost/serialization/access.hpp>
#include <boost/serialization/array.hpp>
#include <boost/serialization/base_object.hpp>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <type_traits>
#include <cstddef>

#include "zallocator.h"

namespace crypto {
    class DH_Keypair;

    template<typename T, std::size_t N>
    struct secure_array : public std::array<T, N> {
        static_assert(std::is_trivial_v<T>);

        ~secure_array() { OPENSSL_cleanse(this->data(), this->size() * sizeof(T)); }

        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive& ar, const unsigned int version) {
            boost::ignore_unused_variable_warning(version);
            const auto data = this->data();
            for (size_t i = 0; i < N; ++i) {
                ar& data[i];
            }
        }
    };
    template<std::size_t N>
    std::ostream& operator<<(std::ostream& os, const secure_array<std::byte, N>& arr) {
        const auto data = arr.data();
        for (size_t i = 0; i < N; ++i) {
            os << std::hex << std::to_integer<unsigned int>(data[i]);
        }
        return os;
    }


    template<typename T>
    using secure_vector = std::vector<T, zallocator<T>>;
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;
    template<typename Key, typename T>
    using secure_map = std::map<Key, T, std::less<Key>, zallocator<std::pair<const Key, T>>>;
    template<typename Key, typename T>
    using secure_unordered_map = std::unordered_map<Key, T, boost::hash<Key>, std::equal_to<Key>,
            zallocator<std::pair<const Key, T>>>;

    std::ostream& operator<<(std::ostream& os, const secure_vector<std::byte>& vec);
    std::ostream& operator<<(std::ostream& os, const DH_Keypair& dh);

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

    [[nodiscard]] bool verify_signed_key(const signature& signature, const public_key& signed_key,
            const public_key& public_signing_key);

    const secure_vector<std::byte> encrypt(const secure_vector<std::byte>& message,
            const shared_key& key, const secure_vector<std::byte>& aad);
    const secure_vector<std::byte> decrypt(secure_vector<std::byte>& ciphertext,
            const shared_key& key, const secure_vector<std::byte>& aad);

    const secure_vector<std::byte> encrypt_password(const secure_vector<std::byte>& message, const secure_string& password);
    const secure_vector<std::byte> decrypt_password(const secure_vector<std::byte>& ciphertext, const secure_string& password);

    const shared_key root_derive(shared_key& root_key, const shared_key& dh_output);
    const shared_key chain_derive(shared_key& chain_key);
    const shared_key x3dh_derive(const secure_vector<std::byte>& key_material);

    const shared_key password_derive(const secure_string& password);

    template<typename T, std::size_t N>
    std::size_t hash_value(const secure_array<T, N>& arr) noexcept {
        return boost::hash_range(arr.cbegin(), arr.cend());
    }

    //Use SHA256 since it's a good universal hash, and anything that needs SHA512 or equivalent will use it inline, rather than using this interface
    std::array<std::byte, 32> hash_data_impl(const unsigned char* data, const std::size_t len);

    template<typename T>
    std::array<std::byte, 32> hash_data(const std::vector<T>& data) {
        static_assert(std::is_trivial_v<T>);
        return hash_data_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    template<typename T, std::size_t N>
    std::array<std::byte, 32> hash_data(const std::array<T, N>& data) {
        static_assert(std::is_trivial_v<T>);
        return hash_data_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    template<typename T>
    std::array<std::byte, 32> hash_data(const secure_vector<T>& data) {
        static_assert(std::is_trivial_v<T>);
        return hash_data_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    template<typename T, std::size_t N>
    std::array<std::byte, 32> hash_data(const secure_array<T, N>& data) {
        static_assert(std::is_trivial_v<T>);
        return hash_data_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    static inline std::array<std::byte, 32> hash_string(const std::string_view data) {
        return hash_data_impl(reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }
} // namespace crypto

#endif
