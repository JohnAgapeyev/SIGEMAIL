#include <algorithm>
#include <list>

#include "device_record.h"

[[nodiscard]] bool device_record::delete_session(const session& s) {
    if (s == *active_session) {
        session_list.erase(active_session);
        //Set active session to known invalid location
        active_session = session_list.end();
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

    if (active_session != session_list.end()) {
        //Move current session to the front of the inactive list
        auto active_tmp = *active_session;
        session_list.erase(active_session);
        session_list.push_front(std::move(active_tmp));
    }
    //Set given session as the active one
    active_session = it;
}
