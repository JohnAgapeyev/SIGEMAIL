#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"
#include "message.h"
#include "session.h"
#include "test.h"

//I trust the OpenSSL implementation, this is mostly just to ensure no exceptions are thrown, or memory is leaked

BOOST_AUTO_TEST_SUITE(hash_tests)

BOOST_AUTO_TEST_CASE(empty_hash) {
    //Force the message to be empty
    std::vector<std::byte> m;
    m.clear();

    const auto h1 = crypto::hash_data(m);

    std::array<std::byte, 0> m2;

    const auto h2 = crypto::hash_data(m2);

    BOOST_TEST(h1 == h2);
}

BOOST_AUTO_TEST_CASE(basic_hash) {
    const auto m = get_message();

    const auto h1 = crypto::hash_data(m);
    const auto h2 = crypto::hash_data(m);

    BOOST_TEST(h1 == h2);
}

BOOST_AUTO_TEST_CASE(diff_hash) {
    const auto m = get_message();
    const auto m2 = get_key();

    const auto h1 = crypto::hash_data(m);
    const auto h2 = crypto::hash_data(m2);

    BOOST_TEST(h1 != h2);
}

BOOST_AUTO_TEST_CASE(modified_hash) {
    auto m1 = get_message();
    auto m2 = get_message();

    m2[2] <<= 2;

    const auto h1 = crypto::hash_data(m1);
    const auto h2 = crypto::hash_data(m2);

    BOOST_TEST(h1 != h2);
}

BOOST_AUTO_TEST_CASE(string_hash) {
    const auto m = "foobar";

    const auto h1 = crypto::hash_string(m);
    const auto h2 = crypto::hash_string(m);

    BOOST_TEST(h1 == h2);
}

BOOST_AUTO_TEST_SUITE_END()
