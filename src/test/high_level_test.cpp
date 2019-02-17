#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "client_state.h"
#include "device.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(high_level_tests)

BOOST_AUTO_TEST_CASE(single_send_recv) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});

    const auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());

    const auto d_m = *decrypted;

    BOOST_TEST(d_m.size() == 1);
}

#if 0
BOOST_AUTO_TEST_CASE(double_send_recv) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    device d{"localhost", "8443", client_db};

    const auto plaintext = get_message();

    d.send_signal_message(plaintext, {"foobar@test.com"});
    d.send_signal_message(plaintext, {"foobar@test.com"});

    const auto decrypted = d.receive_signal_message();
    BOOST_TEST(decrypted.has_value());
}
#endif

BOOST_AUTO_TEST_SUITE_END()
