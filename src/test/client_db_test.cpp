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

BOOST_AUTO_TEST_CASE(remove_device_record) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.remove_device_record(1);
}

BOOST_AUTO_TEST_CASE(remove_device_record_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.remove_device_record(-1);
}

BOOST_AUTO_TEST_CASE(remove_device_record_empty_table) {
    auto db = get_client_db();
    db.remove_device_record(-1);
}

BOOST_AUTO_TEST_CASE(remove_one_time) {
    auto db = get_client_db();
    const crypto::DH_Keypair k;
    db.add_one_time(k);
    db.remove_one_time(k.get_public());
}

BOOST_AUTO_TEST_CASE(remove_one_time_bad_public_key) {
    auto db = get_client_db();
    const crypto::DH_Keypair k;
    db.add_one_time(k);
    db.remove_one_time({});
}

BOOST_AUTO_TEST_CASE(remove_one_time_empty_table) {
    auto db = get_client_db();
    db.remove_one_time({});
}

BOOST_AUTO_TEST_CASE(remove_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.remove_session(1);
}

BOOST_AUTO_TEST_CASE(remove_session_bad_id) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.remove_session(-1);
}

BOOST_AUTO_TEST_CASE(remove_session_empty_table) {
    auto db = get_client_db();
    db.remove_session(-1);
}

BOOST_AUTO_TEST_CASE(activate_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(1, 1);
}

BOOST_AUTO_TEST_CASE(activate_session_existing) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(1, 1);
    db.activate_session(1, 1);
}

BOOST_AUTO_TEST_CASE(activate_session_bad_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    BOOST_REQUIRE_THROW(db.activate_session(1, -1), db_error);
}

BOOST_AUTO_TEST_CASE(activate_session_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(-1, 1);
}

BOOST_AUTO_TEST_CASE(activate_session_empty_sessions) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.activate_session(1, 1), db_error);
}

BOOST_AUTO_TEST_CASE(activate_session_two) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.add_session("foobar@test.com", 1, get_session());
    db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(1, 1);
    db.activate_session(1, 2);
}

BOOST_AUTO_TEST_CASE(mark_user_stale) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.mark_user_stale("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(mark_user_stale_bad) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.mark_user_stale("foobar@fdoobar.com");
}

BOOST_AUTO_TEST_CASE(mark_user_stale_empty) {
    auto db = get_client_db();
    db.mark_user_stale("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(mark_device_stale) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.mark_device_stale(1);
}

BOOST_AUTO_TEST_CASE(mark_device_stale_bad) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.mark_device_stale(-1);
}

BOOST_AUTO_TEST_CASE(mark_device_stale_empty_table) {
    auto db = get_client_db();
    db.mark_device_stale(-1);
}

BOOST_AUTO_TEST_CASE(mark_user_device_stale) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.mark_device_stale(1);
    db.mark_user_stale("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(purge_nothing) {
    auto db = get_client_db();
    db.purge_stale_records();
}

BOOST_AUTO_TEST_CASE(purge_stale_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.mark_user_stale("foobar@test.com");
    db.purge_stale_records();
}

BOOST_AUTO_TEST_CASE(purge_stale_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.mark_device_stale(1);
    db.purge_stale_records();
}

BOOST_AUTO_TEST_CASE(purge_stale_both) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com");
    db.mark_device_stale(1);
    db.mark_user_stale("foobar@test.com");
    db.purge_stale_records();
}

BOOST_AUTO_TEST_SUITE_END()
