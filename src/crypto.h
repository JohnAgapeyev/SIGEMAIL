#ifndef CRYPTO_H
#define CRYPTO_H

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/container_hash/hash.hpp>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <type_traits>

#include "zallocator.h"

namespace crypto {
    class DH_Keypair;

    class openssl_error : public std::exception {
    public:
        openssl_error(unsigned long e) : err_code(e) {}
        ~openssl_error() = default;
        openssl_error(const openssl_error&) = default;
        openssl_error(openssl_error&&) = default;
        openssl_error& operator=(openssl_error&&) = default;
        openssl_error& operator=(const openssl_error&) = default;

        const char* what() const noexcept { return ERR_error_string(err_code, nullptr); }

    private:
        unsigned long err_code;
    };

    class expected_error : public std::exception {
    public:
        expected_error(const char* what) : mesg(what) {}
        ~expected_error() = default;
        expected_error(const expected_error&) = default;
        expected_error(expected_error&&) = default;
        expected_error& operator=(expected_error&&) = default;
        expected_error& operator=(const expected_error&) = default;

        const char* what() const noexcept { return mesg; }

    private:
        const char* mesg;
    };

    template<typename T, std::size_t N>
    struct secure_array : public std::array<T, N> {
        ~secure_array() { OPENSSL_cleanse(this->data(), this->size() * sizeof(T)); }
    };

    template<typename T>
    using secure_vector = std::vector<T, zallocator<T>>;
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;
    template<typename Key, typename T>
    using secure_map = std::map<Key, T, std::less<Key>, zallocator<std::pair<const Key, T>>>;
    template<typename Key, typename T>
    using secure_unordered_map = std::unordered_map<Key, T, boost::hash<Key>, std::equal_to<Key>,
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

    [[nodiscard]] bool verify_signed_key(const signature& signature, const public_key& signed_key,
            const public_key& public_signing_key);

    const secure_vector<std::byte> encrypt(const secure_vector<std::byte>& message,
            const shared_key& key, const secure_vector<std::byte>& aad);
    const secure_vector<std::byte> decrypt(secure_vector<std::byte>& ciphertext,
            const shared_key& key, const secure_vector<std::byte>& aad);

    const shared_key root_derive(shared_key& root_key, const shared_key& dh_output);
    const shared_key chain_derive(shared_key& chain_key);
    const shared_key x3dh_derive(const secure_vector<std::byte>& key_material);

    template<typename T, std::size_t N>
    std::size_t hash_value(const secure_array<T, N>& arr) noexcept {
        return boost::hash_range(arr.cbegin(), arr.cend());
    }

    //Use SHA256 since it's a good universal hash, and anything that needs SHA512 or equivalent will use it inline, rather than using this interface
    static inline std::array<std::byte, 32> hash_data_impl(
            const unsigned char* data, const std::size_t len) {
        std::array<std::byte, 32> hash;

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{
                EVP_MD_CTX_new(), &EVP_MD_CTX_free};

        if (ctx.get() == NULL) {
            throw std::bad_alloc();
        }
        if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL)) {
            throw openssl_error(ERR_get_error());
        }
        if (!EVP_DigestUpdate(ctx.get(), data, len)) {
            throw openssl_error(ERR_get_error());
        }
        if (!EVP_DigestFinal_ex(
                    ctx.get(), reinterpret_cast<unsigned char*>(hash.data()), nullptr)) {
            throw openssl_error(ERR_get_error());
        }
        return hash;
    }

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

    static inline std::string base64_encode_impl(const unsigned char* data, const std::size_t len) {
#if 0
        if (len == 0) {
            throw std::runtime_error("Tried to base64 encode an empty string");
        }
        std::unique_ptr<unsigned char[]> tmp_buf{new unsigned char[(((len / 3) + 1) * 4) + 1 + (len / 64)]};
        int size;
        if ((size = EVP_EncodeBlock(tmp_buf.get(), data, len)) == -1) {
            throw openssl_error(ERR_get_error());
        }
        std::string out;
        //out.assign(&tmp_buf[0], &tmp_buf[size]);

        for (int i = 0; i < size; ++i) {
            out.push_back(tmp_buf[i]);
        }

        return out;
#else
        auto val = std::string{reinterpret_cast<const char *>(data), len};
        using namespace boost::archive::iterators;
        using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
        auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
        return tmp.append((3 - val.size() % 3) % 3, '=');
#endif
    }

    template<typename T>
    static inline std::string base64_encode(const std::vector<T>& data) {
        static_assert(std::is_trivial_v<T>);
        return base64_encode_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    template<typename T>
    static inline std::string base64_encode(const secure_vector<T>& data) {
        static_assert(std::is_trivial_v<T>);
        return base64_encode_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    template<typename T, std::size_t N>
    static inline std::string base64_encode(const std::array<T, N>& data) {
        static_assert(std::is_trivial_v<T>);
        return base64_encode_impl(
                reinterpret_cast<const unsigned char*>(data.data()), data.size() * sizeof(T));
    }
    static inline std::vector<std::byte> base64_decode_impl(
            const unsigned char* data, const std::size_t len) {
#if 0
        if (len == 0) {
            throw std::runtime_error("Tried to base64 decode an empty string");
        }
        std::unique_ptr<unsigned char[]> tmp_buf{new unsigned char[len]};
        int size;
        if ((size = EVP_DecodeBlock(tmp_buf.get(), data, len)) == -1) {
            throw openssl_error(ERR_get_error());
        }
        std::vector<std::byte> out;
        //out.assign(reinterpret_cast<std::byte *>(&tmp_buf[0]), reinterpret_cast<std::byte *>(&tmp_buf[size - 1]));

        for (int i = 0; i < size - 1; ++i) {
            out.push_back(std::byte{tmp_buf[i]});
        }

        return out;
#else
        if (len == 0) {
            throw std::runtime_error("Tried to base64 decode an empty string");
        }
        if (len % 4 != 0) {
            throw std::runtime_error("Tried to base64 decode a corrupted string");
        }
        auto val = std::string{reinterpret_cast<const char *>(data), len};
        using namespace boost::archive::iterators;
        using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

        auto out_str = boost::algorithm::trim_right_copy_if(
                std::string(It(std::begin(val)), It(std::end(val))),
                [](char c) { return c == '\0'; });

        std::vector<std::byte> out;
        for (const auto c : out_str) {
            out.push_back(std::byte{static_cast<unsigned char>(c)});
        }

        return out;
#endif
    }

    static inline std::vector<std::byte> base64_decode(const std::string_view data) {
        return base64_decode_impl(reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }
} // namespace crypto

#endif
