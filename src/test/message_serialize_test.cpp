#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"
#include "key_pack.h"
#include "message.h"
#include "session.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(serialization_tests)

BOOST_AUTO_TEST_CASE(basic_serialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    const auto mesg_str = serialize_message(message);

    const auto deser = deserialize_message(mesg_str);

    BOOST_TEST((message == deser));
}

BOOST_AUTO_TEST_CASE(basic_encode) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    auto mesg_str = serialize_message(message);
    mesg_str[0] = '8';

    BOOST_REQUIRE_THROW(deserialize_message(mesg_str), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
