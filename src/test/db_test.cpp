#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "error.h"
#include "server_state.h"
#include "test.h"

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

BOOST_AUTO_TEST_CASE(add_empty_user) {
    auto db = get_db();
    BOOST_REQUIRE_THROW(db.add_user("", "abcde"), db_error);
}

BOOST_AUTO_TEST_CASE(add_device) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
}

BOOST_AUTO_TEST_CASE(add_device_bad_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    BOOST_REQUIRE_THROW(db.add_device("foo@com", {}, {}, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_device_empty_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    BOOST_REQUIRE_THROW(db.add_device("", {}, {}, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_one_time_key) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.add_one_time_key(1, {});
}

BOOST_AUTO_TEST_CASE(add_one_time_key_bad_index) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    BOOST_REQUIRE_THROW(db.add_one_time_key(-1, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_message) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});

    std::vector<std::byte> m{18, std::byte{0xef}};

    db.add_message("foobar@test.com", 1, m);
}

BOOST_AUTO_TEST_CASE(add_message_bad_device_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    std::vector<std::byte> m{18, std::byte{0xef}};
    BOOST_REQUIRE_THROW(db.add_message("foobar@test.com", -1, m), db_error);
}

BOOST_AUTO_TEST_CASE(add_message_bad_user_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    std::vector<std::byte> m{18, std::byte{0xef}};
    BOOST_REQUIRE_THROW(db.add_message("foobar@com", 1, m), db_error);
}

BOOST_AUTO_TEST_CASE(add_message_empty_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    std::vector<std::byte> m{18, std::byte{0xef}};
    BOOST_REQUIRE_THROW(db.add_message("", 1, m), db_error);
}

BOOST_AUTO_TEST_CASE(add_message_empty_message) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    BOOST_REQUIRE_THROW(db.add_message("foobar@test.com", 1, {}), db_error);
}

BOOST_AUTO_TEST_CASE(add_registration_code) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
}

BOOST_AUTO_TEST_CASE(add_registration_code_empty_email) {
    auto db = get_db();
    BOOST_REQUIRE_THROW(db.add_registration_code("", 12345), db_error);
}

BOOST_AUTO_TEST_CASE(add_registration_code_duplicate_email) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
    BOOST_REQUIRE_THROW(db.add_registration_code("foobar@test.com", 23456), db_error);
}

BOOST_AUTO_TEST_CASE(add_registration_code_duplicate_code) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
    BOOST_REQUIRE_THROW(db.add_registration_code("foo@test", 12345), db_error);
}

BOOST_AUTO_TEST_CASE(update_pre_key) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.update_pre_key(1, {}, {});
}

//Bad ID is ignored by implementation, so it should be a nop
BOOST_AUTO_TEST_CASE(update_pre_key_bad_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.update_pre_key(-1, {}, {});
}

BOOST_AUTO_TEST_CASE(remove_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.remove_user("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_user_and_device) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.remove_user("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_user_and_device_and_one_time) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.add_one_time_key(1, {});
    db.remove_user("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_missing_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.remove_user("foo@test");
}

BOOST_AUTO_TEST_CASE(remove_empty_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.remove_user("");
}

BOOST_AUTO_TEST_CASE(remove_user_empty_table) {
    auto db = get_db();
    db.remove_user("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_device) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.remove_device(1);
}

BOOST_AUTO_TEST_CASE(remove_device_bad_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.remove_device(-1);
}

BOOST_AUTO_TEST_CASE(remove_device_empty_table) {
    auto db = get_db();
    db.remove_device(-1);
}

BOOST_AUTO_TEST_CASE(remove_one_time) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.add_one_time_key(1, {});
    db.remove_one_time_key(1);
}

BOOST_AUTO_TEST_CASE(remove_one_time_bad_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});
    db.add_one_time_key(1, {});
    db.remove_one_time_key(-1);
}

BOOST_AUTO_TEST_CASE(remove_one_time_empty_table) {
    auto db = get_db();
    db.remove_one_time_key(-1);
}

BOOST_AUTO_TEST_CASE(remove_message) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});

    std::vector<std::byte> m{18, std::byte{0xef}};

    db.add_message("foobar@test.com", 1, m);
    db.remove_message(1);
}

BOOST_AUTO_TEST_CASE(remove_message_bad_id) {
    auto db = get_db();
    db.add_user("foobar@test.com", "abcde");
    db.add_device("foobar@test.com", {}, {}, {});

    std::vector<std::byte> m{18, std::byte{0xef}};

    db.add_message("foobar@test.com", 1, m);
    db.remove_message(-1);
}

BOOST_AUTO_TEST_CASE(remove_message_empty_table) {
    auto db = get_db();
    db.remove_message(-1);
}

BOOST_AUTO_TEST_CASE(remove_registration_code) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
    db.remove_registration_code("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(remove_registration_code_bad_email) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
    db.remove_registration_code("foobar@com");
}

BOOST_AUTO_TEST_CASE(remove_registration_code_empty_email) {
    auto db = get_db();
    db.add_registration_code("foobar@test.com", 12345);
    db.remove_registration_code("");
}

BOOST_AUTO_TEST_CASE(remove_registration_code_empty_table) {
    auto db = get_db();
    db.remove_registration_code("foobar@test.com");
}

BOOST_AUTO_TEST_CASE(contact_intersection_single) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");

    std::vector<std::array<std::byte, 24>> hashes;
    hashes.emplace_back(get_truncated_hash("foobar@test.com"));

    const auto intersection = db.contact_intersection(hashes);

    BOOST_TEST(intersection.size() == 1);
    BOOST_TEST(intersection.front() == hashes.front());
}

BOOST_AUTO_TEST_CASE(contact_intersection_multiple) {
    auto db = get_db();

    std::vector<std::string_view> users;
    users.emplace_back("foobar1@test.com");
    users.emplace_back("foobar2@test.com");
    users.emplace_back("foobar3@test.com");
    users.emplace_back("foobar4@test.com");
    users.emplace_back("foobar5@test.com");

    for (const auto& id : users) {
        db.add_user(id, id);
    }

    std::vector<std::array<std::byte, 24>> hashes;
    for (const auto& id : users) {
        hashes.emplace_back(get_truncated_hash(id));
    }

    const auto intersection = db.contact_intersection(hashes);

    std::sort(hashes.begin(), hashes.end());

    BOOST_TEST(intersection.size() == users.size());
    BOOST_TEST(intersection == hashes);
}

BOOST_AUTO_TEST_CASE(contact_intersection_not_all) {
    auto db = get_db();

    std::vector<std::string_view> users;
    users.emplace_back("foobar1@test.com");
    users.emplace_back("foobar2@test.com");

    for (const auto& id : users) {
        db.add_user(id, id);
    }

    std::vector<std::array<std::byte, 24>> hashes;
    for (const auto& id : users) {
        hashes.emplace_back(get_truncated_hash(id));
    }
    hashes.emplace_back(get_truncated_hash("foobar3@test.com"));
    hashes.emplace_back(get_truncated_hash("foobar4@test.com"));
    hashes.emplace_back(get_truncated_hash("foobar5@test.com"));

    const auto intersection = db.contact_intersection(hashes);

    BOOST_TEST(intersection.size() == 2);
}

BOOST_AUTO_TEST_CASE(contact_intersection_none) {
    auto db = get_db();

    std::vector<std::string_view> users;
    users.emplace_back("foobar1@test.com");
    users.emplace_back("foobar2@test.com");
    users.emplace_back("foobar3@test.com");
    users.emplace_back("foobar4@test.com");
    users.emplace_back("foobar5@test.com");

    for (const auto& id : users) {
        db.add_user(id, id);
    }

    std::vector<std::array<std::byte, 24>> hashes;
    hashes.emplace_back(get_truncated_hash("foo3@test.com"));
    hashes.emplace_back(get_truncated_hash("foo4@test.com"));
    hashes.emplace_back(get_truncated_hash("foo5@test.com"));

    const auto intersection = db.contact_intersection(hashes);

    BOOST_TEST(intersection.size() == 0);
}

BOOST_AUTO_TEST_CASE(contact_intersection_empty) {
    auto db = get_db();

    std::vector<std::string_view> users;
    users.emplace_back("foobar1@test.com");
    users.emplace_back("foobar2@test.com");
    users.emplace_back("foobar3@test.com");
    users.emplace_back("foobar4@test.com");
    users.emplace_back("foobar5@test.com");

    for (const auto& id : users) {
        db.add_user(id, id);
    }

    std::vector<std::array<std::byte, 24>> hashes;

    const auto intersection = db.contact_intersection(hashes);

    BOOST_TEST(intersection.size() == 0);
}

BOOST_AUTO_TEST_CASE(contact_intersection_empty_table) {
    auto db = get_db();
    std::vector<std::array<std::byte, 24>> hashes;
    const auto intersection = db.contact_intersection(hashes);
    BOOST_TEST(intersection.size() == 0);
}

BOOST_AUTO_TEST_CASE(confirm_auth) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");
    BOOST_TEST(db.confirm_auth_token("foobar@test.com", "12345"));
}

BOOST_AUTO_TEST_CASE(confirm_auth_bad) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");
    BOOST_TEST(!db.confirm_auth_token("foobar@test.com", "23456"));
}

BOOST_AUTO_TEST_CASE(confirm_auth_wrong) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");
    db.add_user("foobar2@test.com", "23456");
    BOOST_TEST(!db.confirm_auth_token("foobar@test.com", "23456"));
}

BOOST_AUTO_TEST_CASE(confirm_auth_empty_user) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");
    BOOST_TEST(!db.confirm_auth_token("", "23456"));
}

BOOST_AUTO_TEST_CASE(confirm_auth_empty_token) {
    auto db = get_db();
    db.add_user("foobar@test.com", "12345");
    BOOST_TEST(!db.confirm_auth_token("foobar@test.com", ""));
}

BOOST_AUTO_TEST_CASE(confirm_auth_truncated_token) {
    auto db = get_db();
    db.add_user("foobar@test.com", "123456789");
    BOOST_TEST(!db.confirm_auth_token("foobar@test.com", "1234"));
}

BOOST_AUTO_TEST_SUITE_END()
