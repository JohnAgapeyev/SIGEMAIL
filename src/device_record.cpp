#include <algorithm>
#include <list>

#include "device_record.h"

device_record::device_record(const device_record& other) :
        session_list(other.session_list),
        remote_identity_public_key(other.remote_identity_public_key), is_stale(other.is_stale) {
    if (other.active_session) {
        active_session = std::make_unique<session>(*other.active_session);
    } else {
        active_session = nullptr;
    }
}

device_record& device_record::operator=(const device_record& other) {
    session_list = other.session_list;
    remote_identity_public_key = other.remote_identity_public_key;
    is_stale = other.is_stale;
    if (other.active_session) {
        active_session = std::make_unique<session>(*other.active_session);
    } else {
        active_session = nullptr;
    }
    return *this;
}

[[nodiscard]] bool device_record::delete_session(const session& s) {
    if (active_session && s == *active_session) {
        //Delete session object and null out the pointer
        active_session.reset(nullptr);
    } else {
        auto it = std::find(session_list.begin(), session_list.end(), s);
        if (it == session_list.end()) {
            //Session is not found in list of sessions
            throw std::runtime_error("Tried to delete session that did not exist");
        }
        session_list.erase(it);
    }
    return !session_list.empty();
}

void device_record::activate_session(const session& s) {
    auto it = std::find(session_list.begin(), session_list.end(), s);
    if (it == session_list.end()) {
        //Session is not found in list of sessions
        throw std::runtime_error("Tried to active session that did not exist");
    }

    //Move the active session out of the unique ptr and to the front of the inactive list
    session_list.emplace_front(std::move(*active_session.release()));

    session_list.erase(it);
    active_session = std::make_unique<session>(s);
}

bool device_record::operator==(const device_record& other) const {
    if (is_stale != other.is_stale) {
        return false;
    }
    if (*active_session != *(other.active_session)) {
        return false;
    }
    if (remote_identity_public_key != other.remote_identity_public_key) {
        return false;
    }
    if (session_list != other.session_list) {
        return false;
    }
    return true;
}

void device_record::insert_session(session s) {
    session_list.emplace_front(std::move(*active_session.release()));
    active_session = std::make_unique<session>(std::move(s));
}
