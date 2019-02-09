#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "error.h"
#include "server_state.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(client_db_tests)

//Literally just test that the db creation doesn't error and throw
BOOST_AUTO_TEST_CASE(db_creation) {
    auto db = get_db();
}

BOOST_AUTO_TEST_SUITE_END()
