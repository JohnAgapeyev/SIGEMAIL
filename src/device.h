#ifndef DEVICE_H
#define DEVICE_H

#include <array>
#include <boost/container_hash/hash.hpp>
#include <cstdint>
#include <unordered_map>

#include "crypto.h"
#include "device_record.h"
#include "dh.h"
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

private:
    std::unordered_map<user_index, user_record, boost::hash<user_index>> correspondents;
    user_record self;

    crypto::DH_Keypair identity_keypair;
    crypto::DH_Keypair signed_pre_key;
    crypto::signature pre_key_signature;
    crypto::secure_vector<crypto::DH_Keypair> one_time_keys;
};

#endif /* end of include guard: DEVICE_H */
