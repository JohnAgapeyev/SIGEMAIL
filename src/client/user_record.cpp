#include <unordered_map>

#include "user_record.h"

void user_record::insert_device_record(device_record dr) {
    user_devices.emplace(user_devices.size(), std::move(dr));
}

[[nodiscard]] bool user_record::delete_device_record(uint64_t device_index) {
    if (!user_devices.erase(device_index)) {
        throw std::runtime_error("Tried to erase device record that did not exist");
    }
    return !user_devices.empty();
}

bool user_record::operator==(const user_record& other) const {
    if (user_devices != other.user_devices) {
        return false;
    }
    if (is_stale != other.is_stale) {
        return false;
    }
    return true;
}
