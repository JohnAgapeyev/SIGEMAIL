#include <unordered_map>
#include <vector>

#include "device.h"
#include "device_record.h"
#include "user_record.h"

device::device(boost::asio::io_context& ioc, ssl::context& ctx, const char* dest_host,
            const char* dest_port, client::database& db) : client_db(db), network_session(std::make_shared<client_network_session>(ioc, ctx, dest_host, dest_port, client_db)) {
    //Foobar
}

void device::delete_user_record(const std::string& u_index) {
    if (!correspondents.erase(u_index)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
}

void device::delete_device_record(const std::string& u_index, int device_index) {
    auto user_rec = correspondents.at(u_index);
    if (user_rec.delete_device_record(device_index)) {
        delete_user_record(u_index);
    }
}

void device::delete_session(const std::string& u_index, int device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    if (device_rec.delete_session(s)) {
        delete_device_record(u_index, device_index);
    }
}

void device::insert_session(const std::string& u_index, int device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    device_rec.insert_session(s);
}

void device::activate_session(const std::string& u_index, int device_index, const session& s) {
    auto device_rec = correspondents.at(u_index).user_devices.at(device_index);
    device_rec.activate_session(s);
}

void device::mark_user_stale(const std::string& u_index) {
    correspondents.at(u_index).is_stale = true;
}

void device::mark_device_stale(const std::string& u_index, int device_index) {
    correspondents.at(u_index).user_devices.at(device_index).is_stale = true;
}

void device::conditionally_update(
        const std::string& u_index, int device_index, const crypto::public_key& pub_key) {
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
        const std::string& u_index, int device_index, const crypto::public_key& pub_key) {
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

        //Alice
        crypto::DH_Keypair alice_ephemeral;

        //Bob
        crypto::DH_Keypair bob_identity;
        crypto::DH_Keypair bob_pre_key;
        const auto pre_key_sig = crypto::sign_key(bob_identity, bob_pre_key.get_public());
        crypto::DH_Keypair one_time_key;

        //Verify the signature
        if (!crypto::verify_signed_key(
                    pre_key_sig, bob_pre_key.get_public(), bob_identity.get_public())) {
            //Pre key signature failed to verify
            throw std::runtime_error("Bad pre key signature");
        }

        //Generate the sender shared secret
        auto shared_secret = crypto::X3DH_sender(identity_keypair, alice_ephemeral,
                bob_identity.get_public(), bob_pre_key.get_public(), one_time_key.get_public());

        //Insert the session
        insert_session(u_index, device_index, session{shared_secret, bob_pre_key.get_public()});
    }
}

void device::send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::string>& recipients) {

    //TODO This needs to be retrieved from the X3DH agreement somehow
    const crypto::secure_vector<std::byte> aad;

    for (const auto& user_id : recipients) {
        std::map<int, signal_message> device_messages;

        if (const auto it = correspondents.find(user_id); it != correspondents.end() && !it->second.is_stale) {
            for (const auto& [device_id, device_rec] : it->second.user_devices) {
                if (device_rec.is_stale || !device_rec.active_session) {
                    continue;
                }
                auto& sess = *(device_rec.active_session.get());
                const auto ciphertext = sess.ratchet_encrypt(plaintext, aad);

                device_messages.emplace(device_id, ciphertext);
            }
        }
        if (device_messages.empty()) {
            continue;
        }
        //This will eventually have a response I will need to respond to
        send_messages_to_server(user_id, device_messages);

        //TODO add server response, record updating, and exception handling
    }
}

void device::receive_signal_message(const crypto::secure_vector<std::byte>& ciphertext,
        const std::string& user_id, const int device_id) {
    //Foobar
}

/*
 * This function needs to contact the server, and return its response.
 * If successful, we're good, messages sent.
 * If unsuccessful, we should get either bad user_id, or bad device_ids
 * Those error conditions will be handled in send_signal_message, since they require record updates internally
 */
void device::send_messages_to_server(const std::string& user_id, const std::map<int, signal_message>& messages) {
    //Foobar
}
