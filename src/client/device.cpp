#include <unordered_map>
#include <boost/asio/ssl.hpp>
#include <vector>

#include "device.h"
#include "error.h"
#include "client_state.h"
#include "client_network.h"

device::device(const char* dest_host,
            const char* dest_port, client::database& db) : ioc(), ssl(boost::asio::ssl::context::tls),
    client_db(db) {

    ssl.set_default_verify_paths();

    // Verify the remote server's certificate
#ifdef NO_SSL_VERIFY
    ssl.set_verify_mode(ssl::verify_none);
#else
    ssl.set_verify_mode(ssl::verify_peer);
    ssl.set_verify_callback(ssl::rfc2818_verification(dest_host));
#endif

    network_session = std::make_shared<client_network_session>(ioc, ssl, dest_host, dest_port, client_db);
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
    (void)email;
    client_db.add_session(device_index, s);
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
        const std::string& email, int device_index) {
    //This purges stale users and device records
    client_db.purge_stale_records();

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

    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey] = client_db.get_self_data();

    const crypto::DH_Keypair ephemeral_keypair;

    if (server_data.size() != 1) {
        //We got more data than we expected
        throw std::runtime_error("Server returned too much data");
    }

    //Since this is a specific index, there cannot be more than 1 entry
    const auto [device_id, identity_key, pre_key, one_time_key] = server_data.front();

    if (device_id != device_index) {
        //Server gave us a different device
        throw std::runtime_error("Server gave us wrong device info");
    }

    conditionally_update(email, device_id, identity_key);

    crypto::shared_key secret_key;
    if (one_time_key.has_value()) {
        secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key, *one_time_key);
    } else {
        secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key);
    }

    session s{std::move(secret_key), std::move(ephemeral_keypair), std::move(pre_key), std::move(self_identity.get_public()), one_time_key};

    int session_id = client_db.add_session(device_index, std::move(s));
    client_db.activate_session(device_index, session_id);
}

void device::prep_for_encryption(const std::string& email) {
    //This purges stale users and device records
    client_db.purge_stale_records();

    //Grab all devices for that email
    const auto dest_data = network_session->lookup_prekey(email, -1);
    if (!dest_data.has_value()) {
        //Server returned an error
        throw std::runtime_error("Server could not retrieve destination data");
    }
    const auto server_data = *dest_data;

    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey] = client_db.get_self_data();

    for (const auto [device_id, identity_key, pre_key, one_time_key] : server_data) {
        if (device_id == self_device_id) {
            //Don't try and do anything for localhost messages
            continue;
        }
        try {
            client_db.get_active_session(device_id);
            continue;
        } catch(const db_error&) {}

        conditionally_update(email, device_id, identity_key);

        const crypto::DH_Keypair ephemeral_keypair;

        crypto::shared_key secret_key;

        if (one_time_key.has_value()) {
            secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key, *one_time_key);
        } else {
            secret_key = crypto::X3DH_sender(self_identity, ephemeral_keypair, identity_key, pre_key);
        }

        session s{std::move(secret_key), std::move(ephemeral_keypair), std::move(pre_key), std::move(self_identity.get_public()), one_time_key};

        int session_id = client_db.add_session(device_id, std::move(s));
        client_db.activate_session(device_id, session_id);
    }
}

void device::send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
        const crypto::secure_vector<std::string>& recipients) {

    //TODO This needs to be retrieved from the X3DH agreement somehow
    const crypto::secure_vector<std::byte> aad;

    auto trans_lock = client_db.start_transaction();

    try {
        const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey] = client_db.get_self_data();

        /*
         * This needs to follow the following set of steps:
         *  - All devices with an active session for the recipient shall have that message created
         *  - Send messages to the server
         *  - Server may reject messages as invalid due to bad client db data
         *  - In said case, the server will respond with the new official set of data
         *  - If the user does not exist, mark it stale, same with devices
         *  - If there are missing valid devices, prep for encryption, and restart this process
         *
         * Here's my current plan so far:
         * - Active sessions for valid recipients
         *
         * Also we need some exception handling if anything fails
         */
        for (const auto& email : recipients) {
            std::vector<std::pair<int, signal_message>> message_list;

            //This ensures we always have an active session
            prep_for_encryption(email);

            const auto dest_devices = client_db.get_device_ids(email);

            for (const auto device_id : dest_devices) {
                auto [sess_id, session] = client_db.get_active_session(device_id);

                const auto mesg = session.ratchet_encrypt(plaintext, aad);

                message_list.emplace_back(device_id, std::move(mesg));

                //Sync the session back to the database
                client_db.sync_session(sess_id, session);
            }
            if (!network_session->submit_message(email, message_list)) {
                //Message submission failed
                throw std::runtime_error("Failed to submit encrypted messages to server");
            }
        }
        crypto::secure_string string_contents;
        for (const auto b : plaintext) {
            string_contents.push_back(std::to_integer<int>(b));
        }
        client_db.add_message(string_contents);
        client_db.commit_transaction(trans_lock);
        return;
    } catch(...) {
        client_db.rollback_transaction(trans_lock);
    }
}

std::optional<std::vector<crypto::secure_vector<std::byte>>> device::receive_signal_message() {
    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey] = client_db.get_self_data();

    const auto server_data = network_session->retrieve_messages(self_email);
    if (!server_data.has_value()) {
        //Network had an error, or response was empty
        return std::nullopt;
    }

    std::vector<crypto::secure_vector<std::byte>> plaintext_messages;

    auto trans_lock = client_db.start_transaction();

    try {
        for (const auto& [from_email, from_device_id, dest_device_id, mesg] : *server_data) {

            /*
             * This will create all database records for the user
             * So assuming there aren't any invalid device ids, this will work
             * A consequence is that it will create sessions for the devices
             *
             * For existing sessions, I handle it there, so that's fine
             *
             * But for devices we haven't seen yet, it will create a session
             * This session will then have to be overwritten
             */
            prep_for_encryption(from_email);

            auto [sess_id, session] = client_db.get_active_session(from_device_id);

            if (std::holds_alternative<initial_message_header>(mesg.header)) {
                //Initial message
                auto [tmp_s, plaintext] = decrypt_initial_message(mesg, self_identity, self_prekey);
                plaintext_messages.emplace_back(std::move(plaintext));

                //Sync the session back to the database
                client_db.sync_session(sess_id, tmp_s);
                client_db.activate_session(from_device_id, sess_id);
            } else {
                auto plaintext = session.ratchet_decrypt(mesg);
                plaintext_messages.emplace_back(std::move(plaintext));

                //Sync the session back to the database
                client_db.sync_session(sess_id, session);
                client_db.activate_session(from_device_id, sess_id);
            }
        }
        for (const auto& plaintext : plaintext_messages) {
            crypto::secure_string string_contents;
            for (const auto b : plaintext) {
                string_contents.push_back(std::to_integer<int>(b));
            }
            client_db.add_message(string_contents);
        }
        client_db.commit_transaction(trans_lock);
        return plaintext_messages;
    } catch (...) {
        client_db.rollback_transaction(trans_lock);
    }
    return std::nullopt;
}

[[nodiscard]] bool device::check_registration() {
    try {
        const auto data = client_db.get_self_data();
        return true;
    } catch (const db_error&) {
        return false;
    }
}

void device::register_with_server(const std::string& email, const std::string& password) {
    if (check_registration()) {
        //Don't re-register
        return;
    }
    if (!network_session->request_verification_code(email, password)) {
        const auto err_msg = "Failed to request verification code from the server";
        spdlog::error(err_msg);
        throw std::runtime_error(err_msg);
    }
}

void device::confirm_registration(const std::string& email, const std::string& password, const uint64_t registration_code) {
    if (check_registration()) {
        //Don't re-register
        return;
    }
    if (!network_session->verify_verification_code(email, password, registration_code)) {
        const auto err_msg = "Failed to verify verification code to the server";
        spdlog::error(err_msg);
        throw std::runtime_error(err_msg);
    }
}
