#include "device.h"
#include "device_record.h"
#include "user_record.h"

void device::delete_user_record(const user_index& u_index) {
    if (!correspondents.erase(u_index)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
}

void device::delete_device_record(const user_index& u_index, uint64_t device_index) {
    auto user_rec = correspondents.at(u_index);
    if (user_rec.delete_device_record(device_index)) {
        delete_user_record(u_index);
    }
}

void device::delete_session(const user_index& u_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    if (device_rec.delete_session(s)) {
        delete_device_record(u_index, device_index);
    }
}

void device::insert_session(const user_index& u_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    device_rec.insert_session(s);
}

void device::activate_session(const user_index& u_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    device_rec.activate_session(s);
}

void device::mark_user_stale(const user_index& u_index) {
    correspondents.at(u_index).is_stale = true;
}

void device::mark_device_stale(const user_index& u_index, uint64_t device_index) {
    correspondents.at(u_index).user_devices.at(device_index).is_stale = true;
}

void device::conditionally_update(
        const user_index& u_index, uint64_t device_index, const crypto::public_key& pub_key) {
    if (!correspondents.count(u_index)) {
        //User does not exist
        user_record ur;
        correspondents.emplace(u_index, std::move(ur));
    }
    auto user_rec = correspondents.find(u_index)->second;
    if (!user_rec.user_devices.count(device_index)) {
        //Device record does not exist
        device_record dr{pub_key};
        user_rec.user_devices.emplace(device_index, std::move(dr));
    } else if (user_rec.user_devices.find(device_index)->second.remote_identity_public_key
            != pub_key) {
        device_record dr{pub_key};
        user_rec.user_devices.insert_or_assign(device_index, std::move(dr));
    }
}

void device::prep_for_encryption(
        const user_index& u_index, uint64_t device_index, const crypto::public_key& pub_key) {
    if (correspondents.at(u_index).is_stale) {
        delete_user_record(u_index);
    } else if (correspondents.at(u_index).user_devices.at(device_index).is_stale) {
        delete_device_record(u_index, device_index);
    }
    conditionally_update(u_index, device_index, pub_key);

    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    if (!device_rec.active_session) {
        //Create active session here
        //This requires server contact to retrieve key bundle for X3DH to generate shared secret needed for session creation
        //For now, I'm just creating a "default" one that can be used for testing and later modification
        //Scratch that, the usage of the given public key is a pain, so I'll have to revisit this later, once networking is valid

#if 0
        //Alice
        crypto::DH_Keypair alice_ephemeral;

        //Bob
        crypto::DH_Keypair bob_identity;
        crypto::DH_Keypair bob_pre_key;
        const auto pre_key_sig = crypto::sign_key(bob_identity, bob_pre_key.get_public());
        crypto::DH_Keypair one_time_key;

        if (!crypto::verify_signed_key(
                    pre_key_sig, bob_pre_key.get_public(), bob_identity.get_public())) {
            //Pre key signature failed to verify
            throw std::runtime_error("Bad pre key signature");
        }

        auto shared_secret = crypto::X3DH_sender(identity_keypair, alice_ephemeral,
                bob_identity.get_public(), bob_pre_key.get_public(), one_time_key.get_public());

        insert_session(u_index, device_index, session{shared_secret, bob_identity.get_public()});
#endif
    }
}
