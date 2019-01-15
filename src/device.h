#ifndef DEVICE_H
#define DEVICE_H

#include "crypto.h"
#include "session.h"
#include "user_record.h"

/*
 * User indices are their email address strings
 * I was going to use the hashes instead, but considering I need to use those email addresses on the server side
 * it would serve no purpose and only make things slower.
 */
using user_index = std::string;

class device {
public:
    device() = default;
    ~device() = default;
    device(const device&) = default;
    device(device&&) = default;
    device& operator=(device&&) = default;
    device& operator=(const device&) = default;

    void delete_user_record(const user_index& u_index);
    void delete_device_record(const user_index& u_index, uint64_t device_index);
    void delete_session(const user_index& u_index, uint64_t device_index, const session& s);

    void insert_session(const user_index& u_index, uint64_t device_index, const session& s);

    void activate_session(const user_index& u_index, uint64_t device_index, const session& s);

    void mark_user_stale(const user_index& u_index);
    void mark_device_stale(const user_index& u_index, uint64_t device_index);

    void conditionally_update(
            const user_index& u_index, uint64_t device_index, const crypto::public_key& pub_key);

    void prep_for_encryption(
            const user_index& u_index, uint64_t device_index, const crypto::public_key& pub_key);

    void send_signal_message(const crypto::secure_vector<std::byte>& plaintext,
            const crypto::secure_vector<user_index>& recipients);

    void receive_signal_message(const crypto::secure_vector<std::byte>& ciphertext,
            const user_index& user_id, const uint64_t device_id);

private:
    void send_messages_to_server(const user_index& user_id, const std::map<uint64_t, signal_message>& messages);


    std::unordered_map<user_index, user_record, boost::hash<user_index>> correspondents;
    user_record self;

    crypto::DH_Keypair identity_keypair;
    crypto::DH_Keypair signed_pre_key;
    crypto::signature pre_key_signature;
    crypto::secure_vector<crypto::DH_Keypair> one_time_keys;
};

#endif /* end of include guard: DEVICE_H */
