#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"
#include "key_pack.h"
#include "message.h"
#include "session.h"
#include "test.h"

//I trust the OpenSSL implementation, this is mostly just to ensure no exceptions are thrown, or memory is leaked

BOOST_AUTO_TEST_SUITE(base64_tests)

BOOST_AUTO_TEST_CASE(empty_encode) {
    //Force the message to be empty
    std::vector<std::byte> m;
    m.clear();

    std::array<std::byte, 0> m2;

    BOOST_REQUIRE_THROW(crypto::base64_encode(m), std::runtime_error);
    BOOST_REQUIRE_THROW(crypto::base64_encode(m2), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(basic_encode) {
    std::vector<std::byte> m{17, std::byte{0xab}};

    const auto h1 = crypto::base64_encode(m);
    const auto h2 = crypto::base64_encode(m);

    BOOST_TEST(h1 == h2);
}

BOOST_AUTO_TEST_CASE(diff_encode) {
    const std::vector<std::byte> m{17, std::byte{0xab}};
    const std::vector<std::byte> m2{29, std::byte{0xab}};

    const auto h1 = crypto::base64_encode(m);
    const auto h2 = crypto::base64_encode(m2);

    BOOST_TEST(h1 != h2);
}

BOOST_AUTO_TEST_CASE(basic_decode) {
    const std::vector<std::byte> m{17, std::byte{0xab}};

    const auto e = crypto::base64_encode(m);

    const auto d = crypto::base64_decode(e);

    BOOST_TEST(m == d);
}

BOOST_AUTO_TEST_CASE(change_decode) {
    const std::vector<std::byte> m{17, std::byte{0xab}};

    auto e = crypto::base64_encode(m);

    e[2] += 1;

    const auto d = crypto::base64_decode(e);

    BOOST_TEST(m != d);
}

BOOST_AUTO_TEST_CASE(bad_decode) {
    const auto m = "";
    BOOST_REQUIRE_THROW(crypto::base64_decode(m), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(bad_decode_length) {
    //This string needs to be padded but isn't
    const auto m = "Zm9vYmFyCg";
    BOOST_REQUIRE_THROW(crypto::base64_decode(m), crypto::openssl_error);
}

BOOST_AUTO_TEST_SUITE_END()
