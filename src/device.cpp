#include "device.h"
#include "user_record.h"

void device::delete_user_record(uint64_t user_index) {
    if (!correspondents.erase(user_index)) {
        //User index did not exist
        throw std::runtime_error("Tried to delete user record that did not exist");
    }
}
