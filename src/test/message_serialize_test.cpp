#define BOOST_TEST_DYN_LINK
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"
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

BOOST_AUTO_TEST_CASE(bad_serialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    auto mesg_str = serialize_message(message);
    mesg_str[0] = '8';

    BOOST_REQUIRE_THROW(deserialize_message(mesg_str), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(empty_deserialization) {
    const auto mesg_str = "";
    BOOST_REQUIRE_THROW(deserialize_message(mesg_str), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(added_garbage_deserialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    auto mesg_str = serialize_message(message);
    mesg_str.push_back('a');
    mesg_str.push_back(' ');
    mesg_str.push_back('b');
    mesg_str.push_back(' ');
    mesg_str.push_back('c');
    mesg_str.push_back(';');

    const auto deser = deserialize_message(mesg_str);

    BOOST_TEST((message == deser));
}

BOOST_AUTO_TEST_CASE(cutoff_deserialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    auto mesg_str = serialize_message(message);
    for (int i = 0; i < 10; ++i) {
        mesg_str.pop_back();
    }

    BOOST_REQUIRE_THROW(deserialize_message(mesg_str), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(corrupted_deserialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    auto mesg_str = serialize_message(message);
    for (auto& c : mesg_str) {
        c <<= 1;
    }

    BOOST_REQUIRE_THROW(deserialize_message(mesg_str), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(clear_serialization) {
    auto session = get_session();
    const auto message = session.ratchet_encrypt(get_message(), get_aad());

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << message;
    }

    const auto deser = deserialize_message(ss.str());

    BOOST_TEST((message == deser));

    ss.str(std::string{});

    {
        boost::archive::text_oarchive arch{ss};
        arch << message;
    }

    const auto deser2 = deserialize_message(ss.str());

    BOOST_TEST((message == deser2));
}

BOOST_AUTO_TEST_SUITE_END()
