#include "device.h"
#include "device_record.h"
#include "user_record.h"

void device::delete_user_record(uint64_t user_index) {
    if (!correspondents.erase(user_index)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
}

void device::delete_device_record(uint64_t user_index, uint64_t device_index) {
    auto user_rec = correspondents.at(user_index);
    if (user_rec.delete_device_record(device_index)) {
        delete_user_record(user_index);
    }
}

void device::delete_session(uint64_t user_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(user_index).user_devices.at(device_index);
    if (device_rec.delete_session(s)) {
        delete_device_record(user_index, device_index);
    }
}

void device::insert_session(uint64_t user_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(user_index).user_devices.at(device_index);
    device_rec.insert_session(s);
}
