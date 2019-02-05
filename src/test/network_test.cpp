#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(network_tests)

BOOST_AUTO_TEST_CASE(basic_request) {
    auto db = get_db();
    const auto server = get_server(db);
    const auto client = get_client();
    //client->request_verification_code();
}

BOOST_AUTO_TEST_CASE(plenty_requests) {
    auto db = get_db();
    for (int i = 0; i < 100; ++i) {
        const auto server = get_server(db);
        const auto client = get_client();
        //client->request_verification_code();
    }
}

BOOST_AUTO_TEST_SUITE_END()
