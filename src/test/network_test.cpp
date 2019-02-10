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
    const auto server = get_server(server_db);
    const auto client = get_client(client_db);
    //BOOST_TEST(client->request_verification_code("foobar@test.com"));
}

BOOST_AUTO_TEST_CASE(confirm_verification_code) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server = get_server(server_db);
    const auto client = get_client(client_db);

    //db.add_registration_code("foobar@test.com", 12345);

    //BOOST_TEST(client->verify_verification_code(12345));
}

BOOST_AUTO_TEST_SUITE_END()
