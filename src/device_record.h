#ifndef DEVICE_RECORD_H
#define DEVICE_RECORD_H

#include <deque>

#include "crypto.h"
#include "session.h"

class device_record {
public:
    device_record() = default;
    ~device_record() = default;
    device_record(const device_record&) = default;
    device_record(device_record&&) = default;
    device_record& operator=(device_record&&) = default;
    device_record& operator=(const device_record&) = default;

    void set_remote_identity(const crypto::secure_array<std::byte, 32>& identity_key) {
        remote_identity_public_key = identity_key;
    }

private:
    std::deque<session>::iterator active_session;
    std::deque<session> session_list;

    crypto::public_key remote_identity_public_key;

    bool is_stale;
};

#endif /* end of include guard: DEVICE_RECORD_H */
