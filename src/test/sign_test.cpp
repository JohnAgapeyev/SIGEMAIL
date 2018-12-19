#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test.h"
#include "crypto.h"
#include "dh.h"

BOOST_AUTO_TEST_SUITE(sign_tests)

BOOST_AUTO_TEST_CASE(key_sign) {
    const auto key = get_key();

    crypto::DH_Keypair signing_pair;

    const auto signature = crypto::sign_key(signing_pair, key);

    BOOST_TEST(verify_signed_key(signature, key, signing_pair.get_public()));
}

BOOST_AUTO_TEST_CASE(bad_key_signature) {
    const auto key = get_key();

    crypto::DH_Keypair signing_pair;

    auto signature = crypto::sign_key(signing_pair, key);
    signature[2] = std::byte{0x02};
    signature[9] = signature[0];

    BOOST_TEST(verify_signed_key(signature, key, signing_pair.get_public()) == false);
}

BOOST_AUTO_TEST_CASE(verify_wrong_key) {
    const auto key = get_key();

    crypto::DH_Keypair signing_pair;

    const auto signature = crypto::sign_key(signing_pair, key);

    crypto::shared_key diff_key;
    diff_key.fill(std::byte{0xfe});

    BOOST_TEST(verify_signed_key(signature, diff_key, signing_pair.get_public()) == false);
}

BOOST_AUTO_TEST_SUITE_END()
