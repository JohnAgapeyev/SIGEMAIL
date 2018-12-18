#ifndef USER_RECORD_H
#define USER_RECORD_H

#include <unordered_map>

#include "crypto.h"
#include "device_record.h"

class user_record {
public:
    user_record() = default;
    ~user_record() = default;
    user_record(const user_record&) = default;
    user_record(user_record&&) = default;
    user_record& operator=(user_record&&) = default;
    user_record& operator=(const user_record&) = default;

    bool operator==(const user_record& other) const;
    bool operator!=(const user_record& other) const { return !(*this == other); }

    void add_device(device_record dr);
    [[nodiscard]] bool remove_device(uint64_t device_index);
    [[nodiscard]] bool remove_device(const device_record& dr);

private:
    std::unordered_map<uint64_t, device_record> user_devices;
    bool is_stale;
};

#endif /* end of include guard: USER_RECORD_H */
