#include <unordered_map>

#include "user_record.h"

void user_record::add_device(device_record dr) {
    user_devices.emplace(user_devices.size(), std::move(dr));
}

[[nodiscard]] bool user_record::remove_device(uint64_t device_index) {
    user_devices.erase(device_index);
    return !user_devices.empty();
}
