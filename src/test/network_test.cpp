#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(network_tests)

BOOST_AUTO_TEST_CASE(basic_request) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;
    BOOST_TEST(client->request_verification_code("foobar@test.com"));
}

BOOST_AUTO_TEST_CASE(confirm_verification_code) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);

    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
}

BOOST_AUTO_TEST_CASE(register_prekeys) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
    BOOST_TEST(client->register_prekeys(100));
}

BOOST_AUTO_TEST_CASE(lookup_prekeys) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
    BOOST_TEST(client->register_prekeys(10));

    server_db.add_registration_code("foobar2@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar2@test.com", 12345));
    BOOST_TEST(client->register_prekeys(10));

    BOOST_TEST(client->lookup_prekey("foobar2@test.com", 2));
}

BOOST_AUTO_TEST_SUITE_END()
