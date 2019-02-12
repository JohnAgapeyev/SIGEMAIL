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
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;
    BOOST_TEST(client->request_verification_code("foobar@test.com"));
}

BOOST_AUTO_TEST_CASE(confirm_verification_code) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);

    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
}

BOOST_AUTO_TEST_CASE(register_prekeys) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
    BOOST_TEST(client->register_prekeys(100));
}

BOOST_AUTO_TEST_CASE(lookup_prekeys) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));
    BOOST_TEST(client->register_prekeys(10));

    server_db.add_registration_code("foobar2@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar2@test.com", 12345));
    BOOST_TEST(client->register_prekeys(10));

    BOOST_TEST(client->lookup_prekey("foobar2@test.com", 2));
}

BOOST_AUTO_TEST_CASE(contact_intersection) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    server_db.add_registration_code("foobar2@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar2@test.com", 12345));

    server_db.add_registration_code("foobar3@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar3@test.com", 12345));

    std::vector<std::string> contacts;
    contacts.emplace_back("foobar@test.com");
    contacts.emplace_back("foobar3@test.com");
    contacts.emplace_back("foobar5@test.com");

    BOOST_TEST(client->contact_intersection(contacts));
}

BOOST_AUTO_TEST_CASE(submit_message) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{get_key(), recv_pair.get_public()};
    const auto m = send_s.ratchet_encrypt(get_message(), get_aad());

    std::vector<std::pair<uint64_t, signal_message>> messages;

    messages.emplace_back(1, m);

    BOOST_TEST(client->submit_message("foobar@test.com", messages));
}

BOOST_AUTO_TEST_CASE(submit_message_multiple) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{get_key(), recv_pair.get_public()};
    const auto m = send_s.ratchet_encrypt(get_message(), get_aad());

    std::vector<std::pair<uint64_t, signal_message>> messages;
    messages.emplace_back(1, m);
    messages.emplace_back(1, m);
    messages.emplace_back(1, m);
    messages.emplace_back(1, m);
    messages.emplace_back(1, m);

    BOOST_TEST(client->submit_message("foobar@test.com", messages));
}

BOOST_AUTO_TEST_CASE(submit_message_different_dests) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    server_db.add_registration_code("foobar2@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar2@test.com", 12345));

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{get_key(), recv_pair.get_public()};
    const auto m = send_s.ratchet_encrypt(get_message(), get_aad());

    std::vector<std::pair<uint64_t, signal_message>> messages;
    messages.emplace_back(2, m);

    BOOST_TEST(client->submit_message("foobar2@test.com", messages));
}

BOOST_AUTO_TEST_CASE(retrieve_messages) {
    auto server_db = get_server_db();
    auto client_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto client_wrapper = get_client(client_db);
    auto client = client_wrapper->client;

    server_db.add_registration_code("foobar@test.com", 12345);
    BOOST_TEST(client->verify_verification_code("foobar@test.com", 12345));

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{get_key(), recv_pair.get_public()};
    const auto m = send_s.ratchet_encrypt(get_message(), get_aad());

    std::vector<std::pair<uint64_t, signal_message>> messages;
    messages.emplace_back(1, m);

    BOOST_TEST(client->submit_message("foobar@test.com", messages));

    BOOST_TEST(client->retrieve_messages("foobar@test.com"));
}

BOOST_AUTO_TEST_SUITE_END()
