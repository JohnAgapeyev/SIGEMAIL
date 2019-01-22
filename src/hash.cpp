#include "crypto.h"
#include "error.h"

//Use SHA256 since it's a good universal hash, and anything that needs SHA512 or equivalent will use it inline, rather than using this interface
std::array<std::byte, 32> crypto::hash_data_impl(
        const unsigned char* data, const std::size_t len) {
    std::array<std::byte, 32> hash;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};

    if (ctx.get() == NULL) {
        throw std::bad_alloc();
    }
    if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL)) {
        throw openssl_error(ERR_get_error());
    }
    if (!EVP_DigestUpdate(ctx.get(), data, len)) {
        throw openssl_error(ERR_get_error());
    }
    if (!EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(hash.data()), nullptr)) {
        throw openssl_error(ERR_get_error());
    }
    return hash;
}
