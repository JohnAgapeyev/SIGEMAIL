#ifndef ZALLOCATOR_H
#define ZALLOCATOR_H

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <openssl/crypto.h>

namespace crypto {
    template<typename T>
    struct zallocator {
        using allocator_type = zallocator<T>;
        using value_type = T;
        using pointer = value_type*;
        using const_pointer = const value_type*;
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

        pointer address(reference v) const { return &v; }
        const_pointer address(const_reference v) const { return &v; }

        pointer allocate(size_type n, [[maybe_unused]] const void* hint = 0) {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
                throw std::bad_alloc();
            }
            return static_cast<pointer>(::operator new(n * sizeof(value_type)));
        }

        void deallocate(pointer p, size_type n) {
            OPENSSL_cleanse(p, n * sizeof(T));
            ::operator delete(p);
        }

        size_type max_size() const { return std::numeric_limits<size_type>::max() / sizeof(T); }

        template<typename U, typename... Args>
        void construct(U* ptr, Args&&... args) {
            ::new (static_cast<void*>(ptr)) U(std::forward<Args>(args)...);
        }

        template<typename U>
        void destroy(U* ptr) {
            ptr->~U();
        }

        template<typename OtherAlloc>
        constexpr bool operator==(const OtherAlloc&) const {
            return false;
        }
        template<typename OtherAlloc>
        constexpr bool operator!=(const OtherAlloc&) const {
            return true;
        }
        constexpr bool operator==(const zallocator<T>&) const { return true; }
        constexpr bool operator!=(const zallocator<T>&) const { return false; }
    };
} // namespace crypto

#endif /* end of include guard: ZALLOCATOR_H */
