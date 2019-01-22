#ifndef ERROR_H
#define ERROR_H

#include <openssl/err.h>
#include <stdexcept>

namespace crypto {

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

} // namespace crypto

#endif /* end of include guard: ERROR_H */
