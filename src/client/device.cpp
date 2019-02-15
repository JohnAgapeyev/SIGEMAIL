#include <unordered_map>
#include <vector>

#include "device.h"
#include "device_record.h"
#include "user_record.h"

device::device(boost::asio::io_context& ioc, ssl::context& ctx, const char* dest_host,
            const char* dest_port, client::database& db) : client_db(db), network_session(std::make_shared<client_network_session>(ioc, ctx, dest_host, dest_port, client_db)) {
    //Foobar
}

void device::delete_user_record(const std::string& email) {
#if 1
    client_db.remove_user_record(email);
#else
    if (!correspondents.erase(email)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
#endif
}

void device::delete_device_record(const std::string& email, int device_index) {
#if 1
    //This currently doesn't recurse to delete unused user records
    client_db.remove_device_record(device_index);
#else
    auto user_rec = correspondents.at(email);
    if (user_rec.delete_device_record(device_index)) {
        delete_user_record(email);
    }
#endif
}

void device::delete_session(const std::string& email, int device_index, const session& s) {
#if 1
    //Currently this needs its interface changed to place nicely
#else
    auto device_rec = correspondents.at(email).user_devices.at(device_index);
    if (device_rec.delete_session(s)) {
        delete_device_record(email, device_index);
    }
#endif
}

void device::insert_session(const std::string& email, int device_index, const session& s) {
#if 1
    client_db.add_session(email, device_index, s);
#else
    auto device_rec = correspondents.at(email).user_devices.at(device_index);
    device_rec.insert_session(s);
#endif
}

void device::activate_session(const std::string& email, int device_index, const session& s) {
#if 1
    //This needs its interface changed to use session ids
    //client_db.activate_session(device_index, s);
#else
    auto device_rec = correspondents.at(email).user_devices.at(device_index);
    device_rec.activate_session(s);
#endif
}

void device::mark_user_stale(const std::string& email) {
#if 1
    client_db.mark_user_stale(email);
#else
    correspondents.at(email).is_stale = true;
#endif
}

void device::mark_device_stale(const std::string& email, int device_index) {
#if 1
    client_db.mark_device_stale(device_index);
#else
    correspondents.at(email).user_devices.at(device_index).is_stale = true;
#endif
}

void device::conditionally_update(
        const std::string& email, int device_index, const crypto::public_key& pub_key) {
#if 1
    client_db.add_user_record(email);
    client_db.add_device_record(email, device_index, pub_key);
#else
    if (!correspondents.count(email)) {
        //User does not exist
        user_record ur;
        correspondents.emplace(email, std::move(ur));
    }
    auto user_rec = correspondents.find(email)->second;
    if (!user_rec.user_devices.count(device_index)) {
        //Device record does not exist
        device_record dr{pub_key};
        user_rec.user_devices.emplace(device_index, std::move(dr));
    } else if (user_rec.user_devices.find(device_index)->second.remote_identity_public_key
            != pub_key) {
        device_record dr{pub_key};
        user_rec.user_devices.insert_or_assign(device_index, std::move(dr));
    }
#endif
}

void device::prep_for_encryption(
        const std::string& email, int device_index, const crypto::public_key& pub_key) {
#if 1
    //This purges stale users and device records
    client_db.purge_stale_records();
#else
    if (correspondents.at(email).is_stale) {
        delete_user_record(email);
    } else if (correspondents.at(email).user_devices.at(device_index).is_stale) {
        delete_device_record(email, device_index);
    }
#endif
    conditionally_update(email, device_index, pub_key);

#if 1
    //This entire section needs to contact the server for data, and the end result must be an active session created and inserted
#else
    auto device_rec = correspondents.at(email).user_devices.at(device_index);
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
        insert_session(email, device_index, session{shared_secret, bob_pre_key.get_public()});
    }
#endif
}

void device::send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::string>& recipients) {

    //TODO This needs to be retrieved from the X3DH agreement somehow
    const crypto::secure_vector<std::byte> aad;

#if 1
    /*
     * This needs to follow the following set of steps:
     *  - All devices with an active session for the recipient shall have that message created
     *  - Send messages to the server
     *  - Server may reject messages as invalid due to bad client db data
     *  - In said case, the server will respond with the new official set of data
     *  - If the user does not exist, mark it stale, same with devices
     *  - If there are missing valid devices, prep for encryption, and restart this process
     *
     *  This will require some modifications to the client db to get everything playing nicely
     */
#else
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
#endif
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
