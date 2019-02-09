#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_state.h"
#include "error.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(client_db_tests)

//Literally just test that the db creation doesn't error and throw
BOOST_AUTO_TEST_CASE(db_creation) {
    auto db = get_client_db();
}

BOOST_AUTO_TEST_CASE(save_registration) {
    auto db = get_client_db();
    db.save_registration("foobar@test.com", 1, "testauth", {}, {});
}

BOOST_AUTO_TEST_CASE(save_registration_empty_user) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.save_registration("", 1, "testauth", {}, {}), db_error);
}

BOOST_AUTO_TEST_CASE(save_registration_empty_auth) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.save_registration("foobar@test.com", 1, "", {}, {}), db_error);
}

BOOST_AUTO_TEST_CASE(save_registration_empty_both) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.save_registration("", 1, "", {}, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(add_user_empty) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.add_user_record(""), db_error);
}

BOOST_AUTO_TEST_CASE(add_user_duplicate) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_user_record("foobar@test.com"), db_error);
}

BOOST_AUTO_TEST_CASE(add_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(add_device_bad_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_device_record("foobar@foobar.com"), db_error);
}

BOOST_AUTO_TEST_CASE(add_device_empty) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.add_device_record(""), db_error);
}

BOOST_AUTO_TEST_CASE(add_device_no_user) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.add_device_record("foobar@foobar.com"), db_error);
}

BOOST_AUTO_TEST_CASE(add_one_time) {
    auto db = get_client_db();
    crypto::DH_Keypair k;
    db.add_one_time(k);
}

BOOST_AUTO_TEST_CASE(add_one_time_duplicate) {
    auto db = get_client_db();
    crypto::DH_Keypair k;
    db.add_one_time(k);
    BOOST_REQUIRE_THROW(db.add_one_time(k), db_error);
}

BOOST_AUTO_TEST_CASE(add_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
}

BOOST_AUTO_TEST_CASE(add_session_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_session("foobar@test.com", -1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_bad_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_session("foobar@foobar.com", 1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_empty_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_session("", 1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_duplicate) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    const auto s = get_session();
    db.add_session("foobar@test.com", 1, s);
    BOOST_REQUIRE_THROW(db.add_session("foobar@test.com", 1, s), db_error);
}

BOOST_AUTO_TEST_CASE(remove_user_record) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.remove_user_record("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_user_record_bad_email) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.remove_user_record("foobar@foobar.com");
}

BOOST_AUTO_TEST_CASE(remove_user_record_empty_table) {
    auto db = get_client_db();
    db.remove_user_record("foobar@foobar.com");
}

BOOST_AUTO_TEST_CASE(remove_user_record_empty_email) {
    auto db = get_client_db();
    db.remove_user_record("");
}

BOOST_AUTO_TEST_SUITE_END()
