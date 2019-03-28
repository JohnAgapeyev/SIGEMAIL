#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "logging.h"
#include "session.h"
#include "test.h"

BOOST_AUTO_TEST_SUITE(session_tests)

BOOST_AUTO_TEST_CASE(session_initial) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    spdlog::debug("Testing initial session message exchange");

    const auto m = send_s.ratchet_encrypt(message, aad);

    //auto [recv_s, plaintext] = decrypt_initial_message(send_s.ratchet_encrypt(message, aad), recv_id, recv_pre);
    auto [recv_s, plaintext] = decrypt_initial_message(m, recv_id, recv_pre);

    spdlog::info("Input plaintext   {}", message);
    spdlog::info("Output ciphertext {}", m.message);
    spdlog::info("Output plaintext  {}", plaintext);

    spdlog::debug("Output plaintext == Input plaintext");
    spdlog::debug("Test OK");

    BOOST_TEST(plaintext == message);
}

BOOST_AUTO_TEST_CASE(session_double_send) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
}

BOOST_AUTO_TEST_CASE(session_initial_back_forth) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);
}

BOOST_AUTO_TEST_CASE(session_double_decrypt) {
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(session_back_and_forth) {
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(out_of_order_messages) {
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    spdlog::debug("Testing Out of Order message handling");

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    spdlog::info("Encrypt message 1");
    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    spdlog::info("Done encrypting message 1");
    spdlog::info("Encrypt message 2");
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);
    spdlog::info("Done encrypting message 2");

    spdlog::info("Decrypt message 2");
    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    spdlog::info("Decryption succeeded");
    spdlog::info("Decrypt message 1");
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
    spdlog::info("Decryption succeeded");

    spdlog::debug("Both messages decrypted successfully");
    spdlog::debug("Test OK");
}

BOOST_AUTO_TEST_CASE(out_of_order_back_and_forth) {
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    const auto message_3 = get_message();
    const auto aad_3 = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_3, aad_3)) == message_3);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}

BOOST_AUTO_TEST_CASE(many_sends) {
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    for (int i = 0; i < 20; ++i) {
        const auto message = get_message();
        const auto aad = get_aad();

        BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    }
}

BOOST_AUTO_TEST_CASE(many_alternating) {
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    for (int i = 0; i < 10; ++i) {
        const auto message_1 = get_message();
        const auto aad_1 = get_aad();

        const auto message_2 = get_message();
        const auto aad_2 = get_aad();

        BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
        BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_2, aad_2)) == message_2);
    }
}

//https://signal.org/docs/specifications/doubleratchet/#double-ratchet
//First example given, performing A1, B1, B2, A3, A4
BOOST_AUTO_TEST_CASE(dh_old_message) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    spdlog::debug("Testing first Signal documentation example");

    //Send once
    //A1
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("A1 sent fine");
    spdlog::info("A1 received fine");
    //Alternate once
    //B1
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("B1 sent fine");
    spdlog::info("B1 received fine");

    //Encrypt message on old DH values
    //B2 on old DH values
    const auto m = recv_s.ratchet_encrypt(message, aad);
    BOOST_TEST(send_s.ratchet_decrypt(m) == message);

    spdlog::info("B2 sent fine");
    spdlog::info("B2 received fine");

    //A3 & A4
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);

    spdlog::info("A3 sent fine");
    spdlog::info("A3 received fine");
    spdlog::info("A4 sent fine");
    spdlog::info("A4 received fine");

    spdlog::info("Decryption succeeded");

    spdlog::debug("All message decrypted successfully");
    spdlog::debug("Test OK");
}

//https://signal.org/docs/specifications/doubleratchet/#out-of-order-messages
//Extended example given, performing A1, B1, B2, A3, A4, B3, B4, A5, but skipped sending of B2 & B3
BOOST_AUTO_TEST_CASE(signal_out_of_order_example) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key
            = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, send_ephem, recv_pre.get_public(), send_id.get_public(), std::nullopt,
            std::vector<std::byte>{}};

    auto [recv_s, plaintext] = decrypt_initial_message(
            send_s.ratchet_encrypt(get_message(), get_aad()), recv_id, recv_pre);

    spdlog::debug("Testing final Signal documentation example");

    //Send once
    //A1
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("A1 sent fine");
    spdlog::info("A1 received fine");
    //Alternate once
    //B1
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("B1 sent fine");
    spdlog::info("B1 received fine");

    //Encrypt message on old DH values
    //B2 on old DH values, not sent
    const auto m_1 = recv_s.ratchet_encrypt(message, aad);

    spdlog::info("B2 sent fine");

    //A3 & A4
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("A3 sent fine");
    spdlog::info("A3 received fine");
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("A4 sent fine");
    spdlog::info("A4 received fine");

    //B3, not sent
    const auto m_2 = recv_s.ratchet_encrypt(message, aad);
    spdlog::info("B3 sent fine");

    //B4
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("B4 sent fine");
    spdlog::info("B4 received fine");

    //A5
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    spdlog::info("A5 sent fine");
    spdlog::info("A5 received fine");

    //B3 out of order
    BOOST_TEST(send_s.ratchet_decrypt(m_2) == message);
    spdlog::info("B3 received fine");

    //B2 out of order
    BOOST_TEST(send_s.ratchet_decrypt(m_1) == message);
    spdlog::info("B2 received fine");

    spdlog::debug("All messages decrypted successfully");
    spdlog::debug("Test OK");
}

BOOST_AUTO_TEST_SUITE_END()
