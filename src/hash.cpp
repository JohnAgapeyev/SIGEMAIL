#include <openssl/sha.h>

#include "crypto.h"

//Use SHA256 since it's a good universal hash, and anything that needs SHA512 or equivalent will use it inline, rather than using this interface
static inline std::array<std::byte, 32> hash_data_impl(
        const unsigned char* data, const std::size_t len) {
    std::array<std::byte, 32> hash;
    SHA256(data, len, reinterpret_cast<unsigned char*>(hash.data()));
    return hash;
}

template<typename T>
std::array<std::byte, 32> crypto::hash_data(const std::vector<T>& data) {
    return hash_data_impl(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

template<typename T, std::size_t N>
std::array<std::byte, 32> crypto::hash_data(const std::array<T, N>& data) {
    return hash_data_impl(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}
