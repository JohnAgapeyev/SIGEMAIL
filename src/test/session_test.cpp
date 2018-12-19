#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "session.h"

BOOST_AUTO_TEST_CASE(session_one_shot) {
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    crypto::secure_vector<std::byte> message;
    message.assign(256, std::byte{'a'});

    crypto::secure_vector<std::byte> aad;
    aad.assign(128, std::byte{'b'});

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message, aad)) == message);
}

BOOST_AUTO_TEST_CASE(session_double_decrypt) {
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    crypto::secure_vector<std::byte> message_1;
    message_1.assign(256, std::byte{'a'});

    crypto::secure_vector<std::byte> aad_1;
    aad_1.assign(128, std::byte{'b'});

    crypto::secure_vector<std::byte> message_2;
    message_2.assign(64, std::byte{'c'});

    crypto::secure_vector<std::byte> aad_2;
    aad_2.assign(16, std::byte{'d'});

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(session_back_and_forth) {
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    crypto::secure_vector<std::byte> message_1;
    message_1.assign(256, std::byte{'a'});

    crypto::secure_vector<std::byte> aad_1;
    aad_1.assign(128, std::byte{'b'});

    crypto::secure_vector<std::byte> message_2;
    message_2.assign(64, std::byte{'c'});

    crypto::secure_vector<std::byte> aad_2;
    aad_2.assign(16, std::byte{'d'});

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    BOOST_TEST(recv_s.ratchet_decrypt(send_s.ratchet_encrypt(message_1, aad_1)) == message_1);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_2, aad_2)) == message_2);
}

BOOST_AUTO_TEST_CASE(out_of_order_messages) {
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    crypto::secure_vector<std::byte> message_1;
    message_1.assign(256, std::byte{'a'});

    crypto::secure_vector<std::byte> aad_1;
    aad_1.assign(128, std::byte{'b'});

    crypto::secure_vector<std::byte> message_2;
    message_2.assign(64, std::byte{'c'});

    crypto::secure_vector<std::byte> aad_2;
    aad_2.assign(16, std::byte{'d'});

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}

BOOST_AUTO_TEST_CASE(out_of_order_back_and_forth) {
    crypto::secure_array<std::byte, 32> key;
    key.fill(std::byte{0xab});

    crypto::DH_Keypair send_pair;
    crypto::DH_Keypair recv_pair;

    crypto::secure_vector<std::byte> message_1;
    message_1.assign(256, std::byte{'a'});

    crypto::secure_vector<std::byte> aad_1;
    aad_1.assign(128, std::byte{'b'});

    crypto::secure_vector<std::byte> message_2;
    message_2.assign(64, std::byte{'c'});

    crypto::secure_vector<std::byte> aad_2;
    aad_2.assign(16, std::byte{'d'});

    crypto::secure_vector<std::byte> message_3;
    message_3.assign(20, std::byte{'e'});

    crypto::secure_vector<std::byte> aad_3;
    aad_3.assign(10, std::byte{'f'});

    session send_s{key, recv_pair.get_public()};
    session recv_s{key, recv_pair};

    const auto m1 = send_s.ratchet_encrypt(message_1, aad_1);
    const auto m2 = send_s.ratchet_encrypt(message_2, aad_2);

    BOOST_TEST(recv_s.ratchet_decrypt(m2) == message_2);
    BOOST_TEST(send_s.ratchet_decrypt(recv_s.ratchet_encrypt(message_3, aad_3)) == message_3);
    BOOST_TEST(recv_s.ratchet_decrypt(m1) == message_1);
}
