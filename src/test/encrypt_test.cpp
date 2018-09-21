#define BOOST_TEST_MODULE SIGEMAIL
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"

BOOST_AUTO_TEST_CASE(basic_encryption) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const unsigned char c : m) {
            out.emplace_back(std::byte{c});
        }
        return out;
    }();
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::secure_vector<std::byte> aad;
    aad.reserve(20);

    const auto ciphertext = crypto::encrypt(message, key, aad);
    auto ciphertext_copy = ciphertext;
    const auto plaintext = crypto::decrypt(ciphertext_copy, key, aad);

    BOOST_TEST(message == plaintext);
}

BOOST_AUTO_TEST_CASE(aad_encryption) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const unsigned char c : m) {
            out.emplace_back(std::byte{c});
        }
        return out;
    }();
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::secure_vector<std::byte> aad;
    for (int i = 0; i < 20; ++i) {
        aad.emplace_back(std::byte{0x43});
    }

    const auto ciphertext = crypto::encrypt(message, key, aad);
    auto ciphertext_copy = ciphertext;
    const auto plaintext = crypto::decrypt(ciphertext_copy, key, aad);

    BOOST_TEST(message == plaintext);
}

BOOST_AUTO_TEST_CASE(corrupted_message) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const unsigned char c : m) {
            out.emplace_back(std::byte{c});
        }
        return out;
    }();
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::secure_vector<std::byte> aad;
    for (int i = 0; i < 20; ++i) {
        aad.emplace_back(std::byte{0x43});
    }

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;
    ciphertext_copy[3] = std::byte{0};
    ciphertext_copy[4] = ciphertext_copy[1];

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(corrupted_aad) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const unsigned char c : m) {
            out.emplace_back(std::byte{c});
        }
        return out;
    }();
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::secure_vector<std::byte> aad;
    for (int i = 0; i < 20; ++i) {
        aad.emplace_back(std::byte{0x43});
    }

    const auto ciphertext = crypto::encrypt(message, key, aad);

    auto ciphertext_copy = ciphertext;

    aad[2] = std::byte{0x00};
    aad[8] = std::byte{0xFF};
    aad[12] = std::byte{0xCA};

    crypto::secure_vector<std::byte> plaintext;
    BOOST_REQUIRE_THROW(plaintext = crypto::decrypt(ciphertext_copy, key, aad), std::runtime_error);
}

