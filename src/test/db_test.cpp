#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test.h"
#include "server_state.h"
#include "error.h"

BOOST_AUTO_TEST_SUITE(db_tests)

//Literally just test that the db creation doesn't error and throw
BOOST_AUTO_TEST_CASE(db_creation) {
    auto db = get_db();
}

BOOST_AUTO_TEST_CASE(add_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
}

BOOST_AUTO_TEST_CASE(add_user_duplicate) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    BOOST_REQUIRE_THROW(db.add_user("foobar@test.com", "12345"), db_error);
}

BOOST_AUTO_TEST_CASE(add_user_empty_auth) {
    auto db = get_db();
    BOOST_REQUIRE_THROW(db.add_user("foobar@test.com", ""), db_error);
}

BOOST_AUTO_TEST_CASE(add_user_dup_auth) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    BOOST_REQUIRE_THROW(db.add_user("test@test.com", "abcde"), db_error);
}

BOOST_AUTO_TEST_SUITE_END()
