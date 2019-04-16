#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "client_network.h"
#include "client_state.h"
#include "device.h"
#include "listener.h"
#include "server_network.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(high_level_tests)

#if 0
BOOST_AUTO_TEST_CASE(single_send_recv) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});

    const auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);
    BOOST_TEST(decrypted->front() == plaintext);
}

BOOST_AUTO_TEST_CASE(double_send_recv) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});
    alice_dev.send_signal_message(plaintext, {bob_email});

    const auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 2);
}

BOOST_AUTO_TEST_CASE(alternate_sends) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});

    auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);
    BOOST_TEST(decrypted->front() == plaintext);

    bob_dev.send_signal_message(plaintext, {alice_email});

    decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);
    BOOST_TEST(decrypted->front() == plaintext);
}

BOOST_AUTO_TEST_CASE(simul_sends) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});
    bob_dev.send_signal_message(plaintext, {alice_email});

    auto decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);
    BOOST_TEST(decrypted->front() == plaintext);

    decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);
    BOOST_TEST(decrypted->front() == plaintext);
}

BOOST_AUTO_TEST_CASE(empty_recv) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    auto decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 0);
}

BOOST_AUTO_TEST_CASE(many_sends) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    const auto count = 20;

    for (int i = 0; i < count; ++i) {
        alice_dev.send_signal_message(plaintext, {bob_email});
    }

    auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == count);
}

BOOST_AUTO_TEST_CASE(many_simul_alternating) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    const auto count = 20;

    for (int i = 0; i < count; ++i) {
        alice_dev.send_signal_message(plaintext, {bob_email});
        bob_dev.send_signal_message(plaintext, {alice_email});
    }

    auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == count);

    decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == count);
}

BOOST_AUTO_TEST_CASE(many_staggered_alternating) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    const auto count = 20;

    for (int i = 0; i < count; ++i) {
        alice_dev.send_signal_message(plaintext, {bob_email});

        auto decrypted = bob_dev.receive_signal_message();

        BOOST_TEST(decrypted.has_value());
        BOOST_TEST(decrypted->size() == 1);

        bob_dev.send_signal_message(plaintext, {alice_email});

        decrypted = alice_dev.receive_signal_message();

        BOOST_TEST(decrypted.has_value());
        BOOST_TEST(decrypted->size() == 1);
    }
}

BOOST_AUTO_TEST_CASE(many_staggered_2_to_1) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    const auto count = 20;

    for (int i = 0; i < count; ++i) {
        alice_dev.send_signal_message(plaintext, {bob_email});
        alice_dev.send_signal_message(plaintext, {bob_email});

        auto decrypted = bob_dev.receive_signal_message();

        BOOST_TEST(decrypted.has_value());
        BOOST_TEST(decrypted->size() == 2);

        bob_dev.send_signal_message(plaintext, {alice_email});

        decrypted = alice_dev.receive_signal_message();

        BOOST_TEST(decrypted.has_value());
        BOOST_TEST(decrypted->size() == 1);
    }
}

#if 0
BOOST_AUTO_TEST_CASE(simul_multiple_sends) {
    auto server_db = get_server_db();
    auto alice_db = get_client_db();
    auto bob_db = get_client_db();
    const auto server_wrapper = get_server(server_db);
    const auto alice_wrapper = get_client(alice_db);
    const auto bob_wrapper = get_client(bob_db);
    auto alice = alice_wrapper->client;
    auto bob = bob_wrapper->client;

    const auto alice_email = "foobar@test.com";
    const auto bob_email = "baz@foobar.com";

    server_db.add_registration_code(alice_email, 12345);
    server_db.add_registration_code(bob_email, 23456);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456));

    device alice_dev{"localhost", "8443", alice_db};
    device bob_dev{"localhost", "8443", bob_db};

    const auto plaintext = get_message();

    alice_dev.send_signal_message(plaintext, {bob_email});
    bob_dev.send_signal_message(plaintext, {alice_email});

    auto decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);

    decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 1);

    alice_dev.send_signal_message(plaintext, {bob_email});
    alice_dev.send_signal_message(plaintext, {bob_email});
    alice_dev.send_signal_message(plaintext, {bob_email});
    alice_dev.send_signal_message(plaintext, {bob_email});
    alice_dev.send_signal_message(plaintext, {bob_email});

    decrypted = bob_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 5);

    bob_dev.send_signal_message(plaintext, {alice_email});
    bob_dev.send_signal_message(plaintext, {alice_email});
    bob_dev.send_signal_message(plaintext, {alice_email});
    bob_dev.send_signal_message(plaintext, {alice_email});
    bob_dev.send_signal_message(plaintext, {alice_email});

    decrypted = alice_dev.receive_signal_message();

    BOOST_TEST(decrypted.has_value());
    BOOST_TEST(decrypted->size() == 5);
}
#endif
#endif

BOOST_AUTO_TEST_CASE(tons_clients) {
    auto server_db = get_server_db();
    const auto server_wrapper = get_server(server_db);

    auto alice_db = get_client_db();
    const auto alice_wrapper = get_client(alice_db);
    auto alice = alice_wrapper->client;
    const auto alice_email = "foobar@test.com";
    server_db.add_registration_code(alice_email, 12345);
    BOOST_TEST(alice->verify_verification_code(alice_email, "foobar", 12345));
    device alice_dev{"localhost", "8443", alice_db};

    const auto plaintext = get_message();

    constexpr int count = 100;
    std::array<std::thread, count> threads;

    for (int i = 0; i < count; ++i) {
        threads[i] = std::thread{[&](int start) {
            auto bob_db = get_client_db();
            const auto bob_wrapper = get_client(bob_db);
            auto bob = bob_wrapper->client;

            std::stringstream ss{"baz@foobar.com"};
            ss << start;
            auto bob_email = ss.str();

            server_db.add_registration_code(bob_email, 23456 + start);
            BOOST_TEST(bob->verify_verification_code(bob_email, "foobar", 23456 + start));
            device bob_dev{"localhost", "8443", bob_db};

            for (int i = 0; i < 50; ++i) {
                bob_dev.send_signal_message(plaintext, {alice_email});
            }
        }, i};
    }

    sleep(1);

    auto decrypted = alice_dev.receive_signal_message();
    do {
        decrypted = alice_dev.receive_signal_message();
    } while (decrypted.has_value() && !decrypted->empty());

    std::cout << "done\n";

    for (auto& t : threads) {
        t.join();
    }
}

BOOST_AUTO_TEST_SUITE_END()
