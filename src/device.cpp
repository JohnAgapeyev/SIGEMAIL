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

void device::activate_session(uint64_t user_index, uint64_t device_index, const session& s) {
    auto device_rec = correspondents.at(user_index).user_devices.at(device_index);
    device_rec.activate_session(s);
}

void device::mark_user_stale(uint64_t user_index) {
    correspondents.at(user_index).is_stale = true;
}

void device::mark_device_stale(uint64_t user_index, uint64_t device_index) {
    correspondents.at(user_index).user_devices.at(device_index).is_stale = true;
}

void device::conditionally_update(
        uint64_t user_index, uint64_t device_index, const crypto::public_key& pub_key) {
    if (!correspondents.count(user_index)) {
        //User does not exist
        user_record ur;
        correspondents.emplace(user_index, std::move(ur));
    }
    auto user_rec = correspondents.find(user_index)->second;
    if (!user_rec.user_devices.count(device_index)) {
        //Device record does not exist
        device_record dr{pub_key};
        user_rec.user_devices.emplace(device_index, std::move(dr));
    } else if (user_rec.user_devices.find(device_index)->second.remote_identity_public_key
            != pub_key) {
        device_record dr{pub_key};
        user_rec.user_devices.insert_or_assign(device_index, std::move(dr));
    }
}

void device::prep_for_encryption(
        uint64_t user_index, uint64_t device_index, const crypto::public_key& pub_key) {
    if (correspondents.at(user_index).is_stale) {
        delete_user_record(user_index);
    } else if (correspondents.at(user_index).user_devices.at(device_index).is_stale) {
        delete_device_record(user_index, device_index);
    }
    conditionally_update(user_index, device_index, pub_key);

    auto device_rec = correspondents.at(user_index).user_devices.at(device_index);
    if (!device_rec.active_session) {
        //Create active session here
        //This requires server contact to retrieve key bundle for X3DH to generate shared secret needed for session creation
    }
}
