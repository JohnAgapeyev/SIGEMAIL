#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <cstdlib>
#include <array>
#include <cstddef>
#include <vector>
#include <map>
#include <unordered_map>
#include <functional>
#include <openssl/crypto.h>

namespace crypto {
    class DH_Keypair;

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

        zallocator() = default;
        ~zallocator() = default;
        zallocator(const zallocator&) = default;
        zallocator(zallocator&&) = default;
        zallocator& operator=(const zallocator&) = default;
        zallocator& operator=(zallocator&&) = default;

        template<typename U>
        zallocator(const zallocator<U>&) {}

        pointer address(reference v) const {return &v;}
        const_pointer address (const_reference v) const {return &v;}

        pointer allocate(size_type n, [[maybe_unused]] const void* hint = 0) {
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

        template <typename OtherAlloc>
        constexpr bool operator==(const OtherAlloc&) const {
            return false;
        }
        template <typename OtherAlloc>
        bool operator==(OtherAlloc&) {
            return false;
        }
        constexpr bool operator==(const zallocator<T>&) const {
            return true;
        }
        bool operator==(zallocator<T>&) {
            return true;
        }
        template <typename OtherAlloc>
        constexpr bool operator!=(const OtherAlloc& al) const {
            return !(*this == al);
        }
        template <typename OtherAlloc>
        bool operator!=(OtherAlloc& al) {
            return !(*this == al);
        }
        constexpr bool operator!=(const zallocator<T>& z) const {
            return !(*this == z);
        }
        bool operator!=(zallocator<T>& z) {
            return !(*this == z);
        }
    };

    template<typename T>
    using secure_vector = std::vector<T, zallocator<T>>;
    template<typename T>
    using secure_string = std::basic_string<char, std::char_traits<char>, zallocator<char>>;
    template<typename Key, typename T>
    using secure_map = std::map<Key, T, std::less<Key>, zallocator<std::pair<const Key, T>>>;
    template<typename Key, typename T>
    using secure_unordered_map = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, zallocator<std::pair<const Key, T>>>;

    template <typename T, std::size_t arr_size>
    class secure_array {
    public:
        using value_type = T;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = value_type&;
        using const_reference = const value_type&;
        using pointer = value_type*;
        using const_pointer = const value_type*;
        using iterator = typename std::array<T, arr_size>::iterator;
        using const_iterator = typename std::array<T, arr_size>::const_iterator;
        using reverse_iterator = typename std::array<T, arr_size>::reverse_iterator;
        using const_reverse_iterator = typename std::array<T, arr_size>::const_reverse_iterator;

        secure_array() = default;

        //template <typename... U>
        //secure_array(U&&... u) : internal_array(std::array<T, arr_size>{std::forward<U>(u)...}) {}

        //template <typename U>
        //secure_array(U&& u) : internal_array(u) {}

        secure_array(const std::array<T, arr_size>& data) : internal_array(data) {}
        secure_array(std::array<T, arr_size>&& data) : internal_array(data) {}

        ~secure_array() {OPENSSL_cleanse(internal_array.data(), internal_array.size() * sizeof(value_type));}
        secure_array(const secure_array<T, arr_size>&) = default;
        secure_array(secure_array<T, arr_size>&&) = default;
        secure_array& operator=(secure_array<T, arr_size>&&) = default;
        secure_array& operator=(const secure_array<T, arr_size>&) = default;
        constexpr bool operator==(const secure_array<T, arr_size>& other) const noexcept {return *this == other;}
        bool operator==(secure_array<T, arr_size>& other) noexcept {return *this == other;}
        constexpr bool operator!=(const secure_array<T, arr_size>& other) const noexcept {return *this != other;}
        bool operator!=(secure_array<T, arr_size>& other) noexcept {return *this != other;}

        constexpr reference operator[](size_type s) {return internal_array[s];}
        constexpr const_reference operator[](const size_type s) const {return internal_array[s];}

        iterator begin() noexcept {return internal_array.begin();}
        constexpr const_iterator begin() const noexcept {return internal_array.begin();}
        constexpr const_iterator cbegin() const noexcept {return internal_array.cbegin();}
        iterator end() noexcept {return internal_array.end();}
        constexpr const_iterator end() const noexcept {return internal_array.end();}
        constexpr const_iterator cend() const noexcept {return internal_array.cend();}

        reverse_iterator rbegin() noexcept {return internal_array.rbegin();}
        constexpr const_reverse_iterator rbegin() const noexcept {return internal_array.rbegin();}
        constexpr const_reverse_iterator crbegin() const noexcept {return internal_array.crbegin();}
        reverse_iterator rend() noexcept {return internal_array.rend();}
        constexpr const_reverse_iterator rend() const noexcept {return internal_array.rend();}
        constexpr const_reverse_iterator crend() const noexcept {return internal_array.crend();}

        constexpr pointer data() noexcept {return internal_array.data();}
        constexpr const_pointer data() const noexcept {return internal_array.data();}

        constexpr reference front() {return internal_array.front();}
        constexpr const_reference front() const {return internal_array.front();}

        constexpr reference back() {return internal_array.back();}
        constexpr const_reference back() const {return internal_array.back();}

        constexpr bool empty() const noexcept {return internal_array.empty();}

        constexpr size_type size() const noexcept {return internal_array.size();}
        constexpr size_type max_size() noexcept {return internal_array.max_size();}
        constexpr size_type max_size() const noexcept {return internal_array.max_size();}

        void fill(const_reference value) {internal_array.fill(value);}

    private:
        std::array<T, arr_size> internal_array;
    };

    const secure_array<std::byte, 32> X3DH(const DH_Keypair& local_identity, const DH_Keypair& local_ephemeral,
            const secure_array<std::byte, 32>& remote_identity, const secure_array<std::byte, 32>& remote_prekey,
            const secure_array<std::byte, 32>& remote_one_time_key);

    const secure_array<std::byte, 64> sign_key(const secure_array<std::byte, 32>& private_signing_key,
            const secure_array<std::byte, 32>& key_to_sign);

    bool verify_signed_key(const secure_array<std::byte, 64>& signature, const secure_array<std::byte, 32>& signed_key,
            const secure_array<std::byte, 32>& public_signing_key);

    void encrypt(const secure_vector<std::byte>& message, const secure_array<std::byte, 32>& key, const secure_vector<std::byte>& aad, secure_vector<std::byte>& ciphertext);
    bool decrypt(secure_vector<std::byte>& ciphertext, const secure_array<std::byte, 32>& key, const secure_vector<std::byte>& aad, secure_vector<std::byte>& plaintext);

    const secure_array<std::byte, 32> root_derive(secure_array<std::byte, 32>& root_key, const secure_array<std::byte, 32>& dh_output);
    const secure_array<std::byte, 32> chain_derive(secure_array<std::byte, 32>& chain_key);
    const secure_array<std::byte, 32> x3dh_derive(const secure_vector<std::byte>& key_material);
}

namespace std {
    template<typename T, std::size_t arr_size>
    class hash<crypto::secure_array<T, arr_size>> {
    public:
        std::size_t operator() (const crypto::secure_array<T, arr_size>& arr) const {
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
        std::size_t operator() (const std::pair<T, U>& p) const {
            return std::hash<T>{}(p.first) ^ std::hash<U>{}(p.second);
        }
    };
}

#endif
