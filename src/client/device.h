#ifndef DEVICE_H
#define DEVICE_H

#include "client_network.h"
#include "client_state.h"
#include "crypto.h"
#include "session.h"

class device {
public:
    device(boost::asio::io_context& ioc, ssl::context& ctx, const char* dest_host,
            const char* dest_port, client::database& db);
    ~device() = default;
    device(const device&) = default;
    device(device&&) = default;
    device& operator=(device&&) = default;
    device& operator=(const device&) = default;

    void delete_user_record(const std::string& email);
    void delete_device_record(const std::string& email, int device_index);
    void delete_session(const std::string& email, int device_index, const int session_id);

    void insert_session(const std::string& email, int device_index, const session& s);

    void activate_session(const std::string& email, int device_index, const int session_id);

    void mark_user_stale(const std::string& email);
    void mark_device_stale(const std::string& email, int device_index);

    void conditionally_update(
            const std::string& email, int device_index, const crypto::public_key& pub_key);

    void prep_for_encryption(
            const std::string& email, int device_index, const crypto::public_key& pub_key);

    void send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
            const crypto::secure_vector<std::string>& recipients);

    void receive_signal_message(const crypto::secure_vector<std::byte>& ciphertext,
            const std::string& user_id, const int device_id);

private:
    client::database& client_db;
    std::shared_ptr<client_network_session> network_session;
};

#endif /* end of include guard: DEVICE_H */
