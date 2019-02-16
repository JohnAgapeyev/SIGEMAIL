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
    db.add_device_record("foobar@test.com", 1, {});
}

BOOST_AUTO_TEST_CASE(add_device_bad_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_device_record("foobar@foobar.com", 1, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_device_empty) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.add_device_record("", 1, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_device_no_user) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.add_device_record("foobar@foobar.com", 1, {}), db_error);
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
    db.add_device_record("foobar@test.com", 1, {});
    BOOST_TEST(db.add_session("foobar@test.com", 1, get_session()) == 1);
}

BOOST_AUTO_TEST_CASE(add_session_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    BOOST_REQUIRE_THROW(db.add_session("foobar@test.com", -1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_bad_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    BOOST_REQUIRE_THROW(db.add_session("foobar@foobar.com", 1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_empty_user) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    BOOST_REQUIRE_THROW(db.add_session("", 1, get_session()), db_error);
}

BOOST_AUTO_TEST_CASE(add_session_duplicate) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
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
    db.add_device_record("foobar@test.com", 1, {});
    db.remove_device_record(1);
}

BOOST_AUTO_TEST_CASE(remove_device_record_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
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
    db.add_device_record("foobar@test.com", 1, {});
    const int sid = db.add_session("foobar@test.com", 1, get_session());
    BOOST_TEST(sid == 1);
    db.remove_session(sid);
}

BOOST_AUTO_TEST_CASE(remove_session_bad_id) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
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
    const int did = 1;
    db.add_device_record("foobar@test.com", did, {});
    const int sid = db.add_session("foobar@test.com", did, get_session());
    db.activate_session(did, sid);
}

BOOST_AUTO_TEST_CASE(activate_session_existing) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    const int did = 1;
    db.add_device_record("foobar@test.com", did, {});
    const int sid = db.add_session("foobar@test.com", did, get_session());
    db.activate_session(did, sid);
    db.activate_session(did, sid);
}

BOOST_AUTO_TEST_CASE(activate_session_bad_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    db.add_session("foobar@test.com", 1, get_session());
    BOOST_REQUIRE_THROW(db.activate_session(1, -1), db_error);
}

BOOST_AUTO_TEST_CASE(activate_session_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const int sid = db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(-1, sid);
}

BOOST_AUTO_TEST_CASE(activate_session_empty_sessions) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    BOOST_REQUIRE_THROW(db.activate_session(1, 1), db_error);
}

BOOST_AUTO_TEST_CASE(activate_session_two) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const int sid1 = db.add_session("foobar@test.com", 1, get_session());
    const int sid2 = db.add_session("foobar@test.com", 1, get_session());
    db.activate_session(1, sid1);
    db.activate_session(1, sid2);
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
    db.add_device_record("foobar@test.com", 1, {});
    db.mark_device_stale(1);
}

BOOST_AUTO_TEST_CASE(mark_device_stale_bad) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    db.mark_device_stale(-1);
}

BOOST_AUTO_TEST_CASE(mark_device_stale_empty_table) {
    auto db = get_client_db();
    db.mark_device_stale(-1);
}

BOOST_AUTO_TEST_CASE(mark_user_device_stale) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
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
    db.add_device_record("foobar@test.com", 1, {});
    db.mark_device_stale(1);
    db.purge_stale_records();
}

BOOST_AUTO_TEST_CASE(purge_stale_both) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    db.mark_device_stale(1);
    db.mark_user_stale("foobar@test.com");
    db.purge_stale_records();
}

BOOST_AUTO_TEST_CASE(get_self) {
    auto db = get_client_db();
    db.save_registration("foobar@test.com", 1, "testauth", {}, {});
    db.get_self_data();
}

BOOST_AUTO_TEST_CASE(get_self_no_data) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.get_self_data(), db_error);
}

BOOST_AUTO_TEST_CASE(get_device_ids) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto ids = db.get_device_ids("foobar@test.com");
    BOOST_TEST(ids.size() == 1);
}

BOOST_AUTO_TEST_CASE(get_device_ids_multiple) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    db.add_device_record("foobar@test.com", 2, {});
    db.add_device_record("foobar@test.com", 3, {});
    db.add_device_record("foobar@test.com", 4, {});
    db.add_device_record("foobar@test.com", 5, {});
    const auto ids = db.get_device_ids("foobar@test.com");
    BOOST_TEST(ids.size() == 5);
}

BOOST_AUTO_TEST_CASE(get_device_ids_empty) {
    auto db = get_client_db();
    const auto ids = db.get_device_ids("foobar@test.com");
    BOOST_TEST(ids.size() == 0);
}

BOOST_AUTO_TEST_CASE(get_device_ids_empty_user) {
    auto db = get_client_db();
    const auto ids = db.get_device_ids("");
    BOOST_TEST(ids.size() == 0);
}

BOOST_AUTO_TEST_CASE(get_one_time) {
    auto db = get_client_db();
    crypto::DH_Keypair k;
    db.add_one_time(k);
    const auto k2 = db.get_one_time_key(k.get_public());
    BOOST_TEST((k == k2));
}

BOOST_AUTO_TEST_CASE(get_one_time_multiple) {
    auto db = get_client_db();
    crypto::DH_Keypair k1;
    db.add_one_time(k1);
    crypto::DH_Keypair k2;
    db.add_one_time(k2);
    crypto::DH_Keypair k3;
    db.add_one_time(k3);
    crypto::DH_Keypair k4;
    db.add_one_time(k4);
    crypto::DH_Keypair k5;
    db.add_one_time(k5);

    BOOST_TEST((db.get_one_time_key(k1.get_public()) == k1));
    BOOST_TEST((db.get_one_time_key(k2.get_public()) == k2));
    BOOST_TEST((db.get_one_time_key(k3.get_public()) == k3));
    BOOST_TEST((db.get_one_time_key(k4.get_public()) == k4));
    BOOST_TEST((db.get_one_time_key(k5.get_public()) == k5));
}

BOOST_AUTO_TEST_CASE(get_one_time_bad) {
    auto db = get_client_db();
    crypto::DH_Keypair k;
    db.add_one_time(k);
    crypto::DH_Keypair k2;
    BOOST_REQUIRE_THROW(const auto k3 = db.get_one_time_key(k2.get_public()), db_error);
}

BOOST_AUTO_TEST_CASE(get_one_time_empty_table) {
    auto db = get_client_db();
    BOOST_REQUIRE_THROW(db.get_one_time_key({}), db_error);
}

BOOST_AUTO_TEST_CASE(get_sessions) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto s = get_session();
    db.add_session("foobar@test.com", 1, s);
    const auto sess_list = db.get_sessions_by_device(1);
    BOOST_TEST((sess_list.size() == 1 && sess_list.front().second == s));
}

BOOST_AUTO_TEST_CASE(get_sessions_multiple) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    for (int i = 0; i < 10; ++i) {
        db.add_session("foobar@test.com", 1, get_session());
    }
    const auto sess_list = db.get_sessions_by_device(1);
    BOOST_TEST((sess_list.size() == 10));
}

BOOST_AUTO_TEST_CASE(get_sessions_bad_device) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    for (int i = 0; i < 10; ++i) {
        db.add_session("foobar@test.com", 1, get_session());
    }
    const auto sess_list = db.get_sessions_by_device(-1);
    BOOST_TEST((sess_list.size() == 0));
}

BOOST_AUTO_TEST_CASE(get_sessions_empty_device_table) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    const auto sess_list = db.get_sessions_by_device(-1);
    BOOST_TEST((sess_list.size() == 0));
}

BOOST_AUTO_TEST_CASE(get_sessions_empty_sessions) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto sess_list = db.get_sessions_by_device(1);
    BOOST_TEST((sess_list.size() == 0));
}

BOOST_AUTO_TEST_CASE(get_active_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto s = get_session();
    const int sid = db.add_session("foobar@test.com", 1, s);
    db.activate_session(1, sid);
    const auto [session_id, active] = db.get_active_session(1);
    BOOST_TEST((s == active));
}

BOOST_AUTO_TEST_CASE(get_active_session_empty) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto s = get_session();
    db.add_session("foobar@test.com", 1, s);
    BOOST_REQUIRE_THROW(db.get_active_session(1), db_error);
}

BOOST_AUTO_TEST_CASE(get_active_session_bad_device_id) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    const auto s = get_session();
    const int sid = db.add_session("foobar@test.com", 1, s);
    db.activate_session(1, sid);
    BOOST_REQUIRE_THROW(db.get_active_session(-1), db_error);
}

BOOST_AUTO_TEST_CASE(sync_session) {
    auto db = get_client_db();
    db.add_user_record("foobar@test.com");
    db.add_device_record("foobar@test.com", 1, {});
    auto s = get_session();
    const int sid = db.add_session("foobar@test.com", 1, s);
    db.activate_session(1, sid);
    auto [sess_id, active] = db.get_active_session(1);
    BOOST_TEST((s == active));

    active.ratchet_encrypt(get_message(), get_aad());
    db.sync_session(sid, active);
    active = db.get_active_session(1).second;

    active.ratchet_encrypt(get_message(), get_aad());
    db.sync_session(sid, active);
    active = db.get_active_session(1).second;
}

BOOST_AUTO_TEST_SUITE_END()
