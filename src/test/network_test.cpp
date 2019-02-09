#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(network_tests)

BOOST_AUTO_TEST_CASE(basic_request) {
    auto db = get_server_db();
    const auto server = get_server(db);
    const auto client = get_client();
    //BOOST_TEST(client->request_verification_code("foobar@test.com"));
}

BOOST_AUTO_TEST_CASE(confirm_verification_code) {
    auto db = get_server_db();
    const auto server = get_server(db);
    const auto client = get_client();

    //db.add_registration_code("foobar@test.com", 12345);

    //BOOST_TEST(client->verify_verification_code(12345));
}

BOOST_AUTO_TEST_SUITE_END()
