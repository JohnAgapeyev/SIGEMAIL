#define BOOST_TEST_MODULE SIGEMAIL
#define BOOST_TEST_DYN_LINK 1
#include <boost/test/unit_test.hpp>

#include "crypto.h"

BOOST_AUTO_TEST_CASE(basic_encryption) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const auto c : m) {
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

    crypto::secure_vector<std::byte> ciphertext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    crypto::encrypt(message, key, aad, ciphertext);

    crypto::secure_vector<std::byte> plaintext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    BOOST_TEST(crypto::decrypt(ciphertext, key, aad, plaintext));
    BOOST_TEST(message == plaintext);
}

BOOST_AUTO_TEST_CASE(aad_encryption) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const auto c : m) {
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

    crypto::secure_vector<std::byte> ciphertext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    crypto::encrypt(message, key, aad, ciphertext);

    crypto::secure_vector<std::byte> plaintext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    BOOST_TEST(crypto::decrypt(ciphertext, key, aad, plaintext));
    BOOST_TEST(message == plaintext);
}

BOOST_AUTO_TEST_CASE(corrupted_message) {
    const crypto::secure_vector<std::byte> message = []() {
        const std::string m = "This is my test message";
        crypto::secure_vector<std::byte> out;
        for (const auto c : m) {
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

    crypto::secure_vector<std::byte> ciphertext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    crypto::encrypt(message, key, aad, ciphertext);

    ciphertext[3] = std::byte{0};
    ciphertext[4] = ciphertext[1];

    crypto::secure_vector<std::byte> plaintext{
            message.size(), std::byte{0}, crypto::zallocator<std::byte>{}};

    BOOST_TEST(crypto::decrypt(ciphertext, key, aad, plaintext) == false);
}
