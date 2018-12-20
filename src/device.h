#ifndef DEVICE_H
#define DEVICE_H

#include <unordered_map>
#include <cstdint>

#include "crypto.h"
#include "dh.h"
#include "user_record.h"
#include "device_record.h"

class device {
public:
    device() = default;
    ~device() = default;
    device(const device&) = default;
    device(device&&) = default;
    device& operator=(device&&) = default;
    device& operator=(const device&) = default;

    void delete_user_record(uint64_t user_index);

    void delete_device_record(uint64_t user_index, uint64_t device_index);

    void delete_session(uint64_t user_index, uint64_t device_index, const session& s);

    void insert_session(uint64_t user_index, uint64_t device_index, const session& s);

private:
    std::unordered_map<uint64_t, user_record> correspondents;
    user_record self;

    crypto::DH_Keypair identity_keypair;
    crypto::DH_Keypair signed_pre_key;
    crypto::signature pre_key_signature;
    crypto::secure_vector<crypto::DH_Keypair> one_time_keys;
};

#endif /* end of include guard: DEVICE_H */
