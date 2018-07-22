#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <cstdlib>
#include <array>
#include <cstddef>
#include <vector>
#include <openssl/crypto.h>

namespace crypto {
    class DH_Keypair;

    void encrypt(const std::vector<std::byte>& message, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag);
    bool decrypt(const std::vector<std::byte>& ciphertext, std::array<std::byte, 16>& tag, const std::array<std::byte, 32>& key, const std::vector<std::byte>& aad, std::vector<std::byte>& plaintext);

    const std::array<std::byte, 32> root_derive(std::array<std::byte, 32>& root_key, const std::array<std::byte, 32>& dh_output);
    const std::array<std::byte, 32> chain_derive(std::array<std::byte, 32>& chain_key);
    const std::array<std::byte, 32> x3dh_derive(const std::vector<std::byte>& key_material);

    //Taken and modified from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#C.2B.2B_Programs
    template <typename T>
    struct zallocator {
        using value_type = T;
        using pointer = value_type *;
        using const_pointer = const value_type *;
        using reference = value_type&;
        using const_reference = const value_type&;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        pointer address(reference v) const {return &v;}
        const_pointer address (const_reference v) const {return &v;}

        pointer allocate(size_type n, const void* hint = 0) {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
                throw std::bad_alloc();
            }
            return static_cast<pointer>(::operator new(n * sizeof(value_type)));
        }

        void deallocate(pointer p, size_type n) {
            OPENSSL_cleanse(p, n*sizeof(T));
            ::operator delete(p);
        }

        size_type max_size() const {
            return std::numeric_limits<size_type>::max() / sizeof(T);
        }

        template<typename U>
        struct rebind {
            typedef zallocator<U> other;
        };

        template<typename U, typename... Args>
        void construct (U *ptr, Args&&... args) {
            ::new(static_cast<void*>(ptr)) U(std::forward<Args>(args)...);
        }

        template<typename U>
        void destroy(U* ptr) {
            ptr->~U();
        }
    };

    const std::array<std::byte, 32> X3DH(const DH_Keypair& local_identity, const DH_Keypair& local_ephemeral,
            const std::array<std::byte, 32>& remote_identity, const std::array<std::byte, 32>& remote_prekey,
            const std::array<std::byte, 32>& remote_one_time_key);

    const std::array<std::byte, 64> sign_key(const std::array<std::byte, 32>& private_signing_key,
            const std::array<std::byte, 32>& key_to_sign);

    bool verify_signed_key(const std::array<std::byte, 64>& signature, const std::array<std::byte, 32>& signed_key,
            const std::array<std::byte, 32>& public_signing_key);

    template<typename T>
    using secure_vector = std::vector<T, zallocator<T>>;
    template<typename T>
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;

    template <typename T, std::size_t size>
    class secure_array {
    public:
        using value_type = T;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = value_type&;
        using const_reference = const value_type&;
        using pointer = value_type*;
        using const_pointer = const value_type*;
        using iterator = typename std::array<T, size>::iterator;
        using const_iterator = typename std::array<T, size>::const_iterator;
        using reverse_iterator = typename std::array<T, size>::reverse_iterator;
        using const_reverse_iterator = typename std::array<T, size>::const_reverse_iterator;

        secure_array() = default;

        template <typename... U>
        secure_array(U&&... u) : data(std::array<T, size>{std::forward<U>(u)...}) {}

        ~secure_array() = default;
        secure_array(const secure_array&) = default;
        secure_array(secure_array&&) = default;
        secure_array& operator=(secure_array&&) = default;
        secure_array& operator=(const secure_array&) = default;

        reference operator[](size_type s) {return data[s];}
        const_reference operator[](const size_type s) const {return data[s];}

        constexpr iterator begin() const {return data.begin();}
        constexpr const_iterator cbegin() const {return data.cbegin();}
        constexpr iterator end() const {return data.end();}
        constexpr const_iterator cend() const {return data.cend();}

        constexpr reverse_iterator rbegin() const {return data.rbegin();}
        constexpr const_reverse_iterator crbegin() const {return data.crbegin();}
        constexpr reverse_iterator rend() const {return data.rend();}
        constexpr const_reverse_iterator crend() const {return data.crend();}

    private:
        std::array<T, size> data;
    };
}

#endif
