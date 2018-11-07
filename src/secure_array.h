#ifndef SECURE_ARRAY_H
#define SECURE_ARRAY_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <openssl/crypto.h>

namespace crypto {
    template<typename T, std::size_t arr_size>
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

        secure_array(const std::array<T, arr_size>& data) : internal_array(data) {}
        secure_array(std::array<T, arr_size>&& data) : internal_array(data) {}

        ~secure_array() {
            OPENSSL_cleanse(internal_array.data(), internal_array.size() * sizeof(value_type));
        }
        secure_array(const secure_array<T, arr_size>&) = default;
        secure_array(secure_array<T, arr_size>&&) = default;
        secure_array& operator=(secure_array<T, arr_size>&&) = default;
        secure_array& operator=(const secure_array<T, arr_size>&) = default;
        constexpr bool operator==(const secure_array<T, arr_size>& other) const noexcept {
            for (size_type i = 0; i < arr_size; ++i) {
                if (internal_array[i] != other[i]) {
                    return false;
                }
            }
            return true;
        }
        constexpr bool operator!=(const secure_array<T, arr_size>& other) const noexcept {
            return !(*this == other);
        }

        constexpr reference operator[](size_type s) { return internal_array[s]; }
        constexpr const_reference operator[](const size_type s) const { return internal_array[s]; }

        constexpr const_iterator begin() const noexcept { return internal_array.begin(); }
        constexpr const_iterator cbegin() const noexcept { return internal_array.cbegin(); }
        constexpr const_iterator end() const noexcept { return internal_array.end(); }
        constexpr const_iterator cend() const noexcept { return internal_array.cend(); }

        constexpr const_reverse_iterator rbegin() const noexcept { return internal_array.rbegin(); }
        constexpr const_reverse_iterator crbegin() const noexcept {
            return internal_array.crbegin();
        }
        constexpr const_reverse_iterator rend() const noexcept { return internal_array.rend(); }
        constexpr const_reverse_iterator crend() const noexcept { return internal_array.crend(); }

        constexpr pointer data() noexcept { return internal_array.data(); }
        constexpr const_pointer data() const noexcept { return internal_array.data(); }

        constexpr reference front() { return internal_array.front(); }
        constexpr const_reference front() const { return internal_array.front(); }

        constexpr reference back() { return internal_array.back(); }
        constexpr const_reference back() const { return internal_array.back(); }

        constexpr bool empty() const noexcept { return internal_array.empty(); }

        constexpr size_type size() const noexcept { return internal_array.size(); }
        constexpr size_type max_size() noexcept { return internal_array.max_size(); }
        constexpr size_type max_size() const noexcept { return internal_array.max_size(); }

        void fill(const_reference value) { internal_array.fill(value); }

    private:
        std::array<T, arr_size> internal_array;
    };
} // namespace crypto

#endif /* end of include guard: SECURE_ARRAY_H */
