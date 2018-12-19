#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test.h"
#include "crypto.h"
#include "session.h"

BOOST_AUTO_TEST_CASE(session_one_shot) {
    const auto key = get_key();
    const auto message = get_message();
    const auto aad = get_aad();

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
}

BOOST_AUTO_TEST_CASE(session_double_decrypt) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(session_back_and_forth) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(out_of_order_messages) {
    const auto key = get_key();
    const auto message_1 = get_message();
    const auto aad_1 = get_aad();

    const auto message_2 = get_message();
    const auto aad_2 = get_aad();

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

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

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_3, aad_3)) == message_3);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}
