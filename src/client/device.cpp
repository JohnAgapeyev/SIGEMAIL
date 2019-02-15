#include <unordered_map>
#include <vector>

#include "device.h"
#include "error.h"
#include "client_state.h"
#include "client_network.h"

device::device(const char* dest_host,
            const char* dest_port, client::database& db) : ioc(), ssl(boost::asio::ssl::context::tls),
    client_db(db), network_session(std::make_shared<client_network_session>(ioc, ssl, dest_host, dest_port, client_db)) {
    //Foobar
}

void device::delete_user_record(const std::string& email) {
    client_db.remove_user_record(email);
}

void device::delete_device_record(const std::string& email, int device_index) {
    (void)email;
    //This currently doesn't recurse to delete unused user records
    client_db.remove_device_record(device_index);
}

void device::delete_session(const std::string& email, int device_index, const int session_id) {
    (void)email;
    (void)device_index;
    client_db.remove_session(session_id);
}

void device::insert_session(const std::string& email, int device_index, const session& s) {
    client_db.add_session(email, device_index, s);
}

void device::activate_session(const std::string& email, int device_index, const int session_id) {
    (void)email;
    client_db.activate_session(device_index, session_id);
}

void device::mark_user_stale(const std::string& email) {
    client_db.mark_user_stale(email);
}

void device::mark_device_stale(const std::string& email, int device_index) {
    (void)email;
    client_db.mark_device_stale(device_index);
}

void device::conditionally_update(
        const std::string& email, int device_index, const crypto::public_key& pub_key) {
    //This section won't overwrite records with different public keys, only creating a new record
    client_db.add_user_record(email);
    client_db.add_device_record(email, device_index, pub_key);
}

void device::prep_for_encryption(
        const std::string& email, int device_index, const crypto::public_key& pub_key) {
    //This purges stale users and device records
    client_db.purge_stale_records();

    conditionally_update(email, device_index, pub_key);

    //This entire section needs to contact the server for data, and the end result must be an active session created and inserted
    try {
        client_db.get_active_session(device_index);
        return;
    } catch(const db_error&) {}
    //Sesssion does not exist, have to contact the server
    //Do it here instead of nested inside the catch
    const auto dest_data = network_session->lookup_prekey(email, device_index);
    if (!dest_data.has_value()) {
        //Server returned an error
        throw std::runtime_error("Server could not retrieve destination data");
    }
    const auto server_data = *dest_data;

    const auto [self_email, self_device_id, auth_token, self_identity, self_prekey] = client_db.get_self_data();

    //Need to somehow save this keypair for later I'm pretty sure
    const crypto::DH_Keypair ephemeral_keypair;

    for (const auto& [device_id, identity_key, pre_key, one_time_key] : server_data) {
        if (device_id != device_index) {
            continue;
        }
        crypto::shared_key secret_key;
        if (one_time_key.has_value()) {
            secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key);
        } else {
            secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key);
        }
        session s{secret_key, pub_key};
        insert_session(email, device_id, s);
    }
}

void device::send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::string>& recipients) {

    //TODO This needs to be retrieved from the X3DH agreement somehow
    const crypto::secure_vector<std::byte> aad;

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
    for (const auto& email : recipients) {
        std::vector<std::pair<int, signal_message>> message_list;
        const auto dest_devices = client_db.get_device_ids(email);
        for (const auto device_id : dest_devices) {
            auto session = client_db.get_active_session(device_id);
            const auto mesg = session.ratchet_encrypt(plaintext, aad);

            //Session needs to be updated back in the database after this
            //Also we need some exception handling if anything fails

            message_list.emplace_back(device_id, std::move(mesg));
        }
        if (!network_session->submit_message(email, message_list)) {
            //Message submission failed
            throw std::runtime_error("Failed to submit encrypted messages to server");
        }
    }
}

std::optional<std::vector<crypto::secure_vector<std::byte>>> device::receive_signal_message() {
    const auto [self_email, self_device_id, auth_token, self_identity, self_prekey] = client_db.get_self_data();

    const auto server_data = network_session->retrieve_messages(self_email);
    if (!server_data.has_value()) {
        //Network had an error, or response was empty
        return std::nullopt;
    }

    auto session = client_db.get_active_session(self_device_id);

    std::vector<crypto::secure_vector<std::byte>> plaintext_messages;

    for (const auto& [device_id, mesg] : *server_data) {
        if (device_id != self_device_id) {
            //Ignore messages we can't decrypt
            continue;
        }
        //This will also need to sync up with the database as well
        auto plaintext = session.ratchet_decrypt(mesg);

        plaintext_messages.emplace_back(std::move(plaintext));
    }

    return plaintext_messages;
}

