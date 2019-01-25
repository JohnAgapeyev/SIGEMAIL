#define BOOST_TEST_MODULE SIGEMAIL
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test.h"
#include "crypto.h"
#include "error.h"
#include "dh.h"

BOOST_TEST_GLOBAL_FIXTURE(DisableLogging);

BOOST_AUTO_TEST_SUITE(encryption_tests)

BOOST_AUTO_TEST_CASE(basic_encryption) {
    const auto message = get_message();
    const auto key = get_key();
    const auto aad = get_aad();

    const auto ciphertext = crypto::encrypt(message, key, aad);
    auto ciphertext_copy = ciphertext;
    const auto plaintext = crypto::decrypt(ciphertext_copy, key, aad);

    BOOST_TEST(message == plaintext);
}

BOOST_AUTO_TEST_CASE(corrupted_message) {
    const auto message = get_message();
    const auto key = get_key();
    const auto aad = get_message();

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;
    ciphertext_copy[3] = std::byte{0};
    ciphertext_copy[4] = ciphertext_copy[1];

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), crypto::expected_error);
}

BOOST_AUTO_TEST_CASE(corrupted_aad) {
    const auto message = get_message();
    const auto key = get_key();
    auto aad = get_message();

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;

    aad[2] = std::byte{0x00};
    aad[8] = std::byte{0xFF};
    aad[12] = std::byte{0xCA};

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), crypto::expected_error);
}

BOOST_AUTO_TEST_CASE(too_short_decrypt) {
    const auto message = get_message();
    const auto key = get_key();
    auto aad = get_message();

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;
    ciphertext_copy.resize(12);

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(bad_key) {
    const auto message = get_message();
    auto key = get_key();
    auto aad = get_message();

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;

    key[2] ^= std::byte{0xcd};

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), crypto::expected_error);
}

BOOST_AUTO_TEST_CASE(bad_nonce) {
    const auto message = get_message();
    const auto key = get_key();
    auto aad = get_message();

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;

    ciphertext_copy[1] <<= 2;

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), crypto::expected_error);
}

BOOST_AUTO_TEST_SUITE_END()
