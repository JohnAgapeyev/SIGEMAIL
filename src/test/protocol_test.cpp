#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "crypto.h"
#include "dh.h"
#include "key_pack.h"
#include "message.h"
#include "protocol_state.h"

BOOST_AUTO_TEST_CASE(x3dh) {
    //Alice
    crypto::DH_Keypair alice_identity;
    crypto::DH_Keypair alice_ephemeral;

    //Bob
    crypto::DH_Keypair bob_identity;
    crypto::DH_Keypair pre_key;
    auto pre_key_sig = crypto::sign_key(bob_identity, pre_key.get_public());
    crypto::DH_Keypair one_time_key;

    //Assume each party has been transmitted the keys via the network by this point

    //Alice key generation
    BOOST_TEST(crypto::verify_signed_key(pre_key_sig, pre_key.get_public(), bob_identity.get_public()));

    auto alice_shared_secret = crypto::X3DH_sender(alice_identity, alice_ephemeral,
            bob_identity.get_public(), pre_key.get_public(), one_time_key.get_public());

    //Assume bob has received alice's keys via an initial message

    //Bob key generation
    auto bob_shared_secret = crypto::X3DH_receiver(bob_identity, pre_key, one_time_key,
            alice_identity.get_public(), alice_ephemeral.get_public());

    BOOST_TEST(alice_shared_secret == bob_shared_secret);
}

BOOST_AUTO_TEST_CASE(bad_x3dh) {
    //Alice
    crypto::DH_Keypair alice_identity;
    crypto::DH_Keypair alice_ephemeral;

    //Bob
    crypto::DH_Keypair bob_identity;
    crypto::DH_Keypair pre_key;
    auto pre_key_sig = crypto::sign_key(bob_identity, pre_key.get_public());
    crypto::DH_Keypair one_time_key;

    //Assume each party has been transmitted the keys via the network by this point

    //Alice key generation
    BOOST_TEST(crypto::verify_signed_key(pre_key_sig, pre_key.get_public(), bob_identity.get_public()));

    auto alice_shared_secret = crypto::X3DH_sender(alice_identity, alice_ephemeral,
            bob_identity.get_public(), pre_key.get_public(), one_time_key.get_public());

    //Assume bob has received alice's keys via an initial message

    //Bob key generation
    //I've swapped the local pre key and identity to make the key derivation fail
    auto bob_shared_secret = crypto::X3DH_receiver(pre_key, bob_identity, one_time_key,
            alice_identity.get_public(), alice_ephemeral.get_public());

    BOOST_TEST(alice_shared_secret != bob_shared_secret);
}

