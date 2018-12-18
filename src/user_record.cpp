#include <unordered_map>

#include "user_record.h"

void user_record::add_device(device_record dr) {
    user_devices.emplace(user_devices.size(), std::move(dr));
}

[[nodiscard]] bool user_record::remove_device(uint64_t device_index) {
    if (!user_devices.erase(device_index)) {
        throw std::runtime_error("Tried to erase device record that did not exist");
    }
    return !user_devices.empty();
}

[[nodiscard]] bool user_record::remove_device(const device_record& dr) {
    auto device_index = std::find_if(user_devices.begin(), user_devices.end(), [&](const auto& p){return (p.second == dr);})->first;
    return remove_device(device_index);
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
