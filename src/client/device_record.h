#ifndef DEVICE_RECORD_H
#define DEVICE_RECORD_H

#include <list>
#include <memory>

#include "crypto.h"
#include "session.h"

class device_record {
    friend class device;
public:
    ~device_record() = default;
    device_record(const device_record& other);
    device_record(device_record&&) = default;
    device_record& operator=(device_record&&) = default;
    device_record& operator=(const device_record& other);

    bool operator==(const device_record& other) const;
    bool operator!=(const device_record& other) const { return !(*this == other); }

private:
    device_record(const crypto::public_key remote_identity) :
            remote_identity_public_key(std::move(remote_identity)) {}

    void insert_session(session s);
    [[nodiscard]] bool delete_session(const session& s);
    void activate_session(const session& s);

    std::unique_ptr<session> active_session;
    std::list<session> session_list;

    crypto::public_key remote_identity_public_key;

    bool is_stale;
};

#endif /* end of include guard: DEVICE_RECORD_H */
