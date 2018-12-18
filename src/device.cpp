#include "device.h"
#include "user_record.h"

void device::delete_user_record(uint64_t user_index) {
    if (!correspondents.erase(user_index)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
}

void device::delete_user_record(const user_record& ur) {
    auto user_index = std::find_if(correspondents.begin(), correspondents.end(), [&](const auto& p){return (p.second == ur);})->first;
    return delete_user_record(user_index);
}

void device::delete_device_record(user_record& ur, const device_record& dr) {
    if (!ur.remove_device(dr)) {
        //Need to delete user record as well
        delete_user_record(ur);
    }
}

void device::delete_session(user_record& ur, device_record& dr, const session& s) {
    if (!dr.delete_session(s)) {
        delete_device_record(ur, dr);
    }
}

void device::insert_session(device_record& dr, const session& s) {
    dr.insert_session(s);
}
