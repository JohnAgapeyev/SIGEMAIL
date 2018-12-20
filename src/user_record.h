#ifndef USER_RECORD_H
#define USER_RECORD_H

#include <unordered_map>

#include "crypto.h"
#include "device_record.h"

class user_record {
    friend class device;
public:
    ~user_record() = default;
    user_record(const user_record&) = default;
    user_record(user_record&&) = default;
    user_record& operator=(user_record&&) = default;
    user_record& operator=(const user_record&) = default;

    bool operator==(const user_record& other) const;
    bool operator!=(const user_record& other) const { return !(*this == other); }

private:
    user_record() = default;
    void insert_device_record(device_record dr);
    [[nodiscard]] bool delete_device_record(uint64_t device_index);

    std::unordered_map<uint64_t, device_record> user_devices;
    bool is_stale;
};

#endif /* end of include guard: USER_RECORD_H */
