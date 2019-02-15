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
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    device d{"localhost", "8443", client_db};

    const auto plaintext = get_message();

    d.send_signal_message(plaintext, {"foobar@test.com"});

    const auto decrypted = d.receive_signal_message();
}

BOOST_AUTO_TEST_SUITE_END()
