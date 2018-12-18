#ifndef DEVICE_RECORD_H
#define DEVICE_RECORD_H

#include <list>

#include "crypto.h"
#include "session.h"

class device_record {
public:
    device_record(const crypto::public_key remote_identity) :
            remote_identity_public_key(std::move(remote_identity)) {}
    ~device_record() = default;
    device_record(const device_record&) = default;
    device_record(device_record&&) = default;
    device_record& operator=(device_record&&) = default;
    device_record& operator=(const device_record&) = default;

    bool operator==(const device_record& other) const;
    bool operator!=(const device_record& other) const { return !(*this == other); }

    [[nodiscard]] bool delete_session(const session& s);

    void activate_session(const session& s);

private:
    std::list<session>::iterator active_session;
    std::list<session> session_list;

    crypto::public_key remote_identity_public_key;

    bool is_stale;
};

#endif /* end of include guard: DEVICE_RECORD_H */
