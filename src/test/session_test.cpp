#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
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

    auto key = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};

    const auto pre_m = send_s.ratchet_encrypt(message, aad);
    const auto [tmp_s, plaintext] = decrypt_initial_message(pre_m, recv_id, recv_pre);

    BOOST_TEST(plaintext == message);
}

BOOST_AUTO_TEST_CASE(session_double_send) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};

    const auto pre_m = send_s.ratchet_encrypt(message, aad);
    auto [tmp_s, plaintext] = decrypt_initial_message(pre_m, recv_id, recv_pre);

    BOOST_TEST(plaintext == message);

    const auto second_m = send_s.ratchet_encrypt(message, aad);

    const auto second_plain = tmp_s.ratchet_decrypt(second_m);

    BOOST_TEST(second_plain == message);
}

BOOST_AUTO_TEST_CASE(session_initial_back_forth) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};

    auto pre_m = send_s.ratchet_encrypt(message, aad);
    auto [tmp_s, plaintext] = decrypt_initial_message(pre_m, recv_id, recv_pre);

    BOOST_TEST(plaintext == message);

    BOOST_TEST((tmp_s == recv_s));

    auto back_m = tmp_s.ratchet_encrypt(message, aad);

    auto next_plain = send_s.ratchet_decrypt(back_m);

    BOOST_TEST(next_plain == message);
}

#if 0
BOOST_AUTO_TEST_CASE(session_one_shot) {
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;

    auto key = crypto::X3DH_sender(send_id, send_ephem, recv_id.get_public(), recv_pre.get_public());

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};

#if 0
    send_s.ratchet_encrypt(message, aad);

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
#else
    const auto pre_m = send_s.ratchet_encrypt(message, aad);

    const auto [tmp_s, plaintext] = decrypt_initial_message(pre_m, recv_id, recv_pre);

    BOOST_TEST(plaintext == message);

    //BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
#endif
}

BOOST_AUTO_TEST_CASE(session_double_decrypt) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(session_back_and_forth) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(out_of_order_messages) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}

BOOST_AUTO_TEST_CASE(out_of_order_back_and_forth) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    const auto message_3 = get_message();
    const auto aad_3 = get_aad();

#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_3, aad_3)) == message_3);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}

BOOST_AUTO_TEST_CASE(many_sends) {
    const auto key = get_key();
#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    for (int i = 0; i < 20; ++i) {
        const auto message = get_message();
        const auto aad = get_aad();

        BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    }
}

BOOST_AUTO_TEST_CASE(many_alternating) {
    const auto key = get_key();
#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

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
    const auto key = get_key();
    const auto message = get_message();
    const auto aad = get_aad();

#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    //Send once
    //A1
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    //Alternate once
    //B1
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);

    //Encrypt message on old DH values
    //B2 on old DH values
    const auto m = recv_s.ratchet_encrypt(message, aad);
    BOOST_TEST(send_s.ratchet_decrypt(m) == message);

    //A3 & A4
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
}

//https://signal.org/docs/specifications/doubleratchet/#out-of-order-messages
//Extended example given, performing A1, B1, B2, A3, A4, B3, B4, A5, but skipped sending of B2 & B3
BOOST_AUTO_TEST_CASE(signal_out_of_order_example) {
    const auto key = get_key();
    const auto message = get_message();
    const auto aad = get_aad();
#if 0
    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};
#else
    crypto::DH_Keypair send_id;
    crypto::DH_Keypair send_ephem;

    crypto::DH_Keypair recv_id;
    crypto::DH_Keypair recv_pre;
    crypto::DH_Keypair recv_one;

    session send_s{key, recv_pre.get_public(), send_id.get_public(), send_ephem.get_public(), std::nullopt};
    session recv_s{key, recv_pre};
#endif

    //Send once
    //A1
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    //Alternate once
    //B1
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);

    //Encrypt message on old DH values
    //B2 on old DH values, not sent
    const auto m_1 = recv_s.ratchet_encrypt(message, aad);

    //A3 & A4
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);

    //B3, not sent
    const auto m_2 = recv_s.ratchet_encrypt(message, aad);

    //B4
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message, aad)) == message);

    //A5
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);

    //B3 out of order
    BOOST_TEST(send_s.ratchet_decrypt(m_2) == message);

    //B2 out of order
    BOOST_TEST(send_s.ratchet_decrypt(m_1) == message);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
