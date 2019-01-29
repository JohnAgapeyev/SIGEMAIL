#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(network_tests)

BOOST_AUTO_TEST_CASE(basic_request) {
    const auto server = get_server();
    const auto client = get_client();

    client->cns->test_request();
}

BOOST_AUTO_TEST_SUITE_END()
