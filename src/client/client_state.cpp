#include <algorithm>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <iterator>
#include <sqlite3.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include "client_state.h"
#include "crypto.h"
#include "db_utils.h"
#include "error.h"
#include "logging.h"

client::database::database(const char* db_name) {
    if (sqlite3_open(db_name, &db_conn) != SQLITE_OK) {
        throw db_error(sqlite3_errmsg(db_conn));
    }

    exec_statement(db_conn, create_self);
    exec_statement(db_conn, create_users);
    exec_statement(db_conn, create_devices);
    exec_statement(db_conn, create_one_time);
    exec_statement(db_conn, create_sessions);

    prepare_statement(db_conn, insert_self, &self_insert);
    prepare_statement(db_conn, insert_users, &users_insert);
    prepare_statement(db_conn, insert_devices, &devices_insert);
    prepare_statement(db_conn, insert_one_time, &one_time_insert);
    prepare_statement(db_conn, insert_sessions, &sessions_insert);

    prepare_statement(db_conn, update_users, &users_update);
    prepare_statement(db_conn, update_devices, &devices_update);
    prepare_statement(db_conn, update_devices_active, &devices_update_active);
    prepare_statement(db_conn, update_sessions, &sessions_update);

    prepare_statement(db_conn, delete_sessions, &sessions_delete);
    prepare_statement(db_conn, delete_users, &users_delete);
    prepare_statement(db_conn, delete_one_time, &one_time_delete);
    prepare_statement(db_conn, delete_devices, &devices_delete);

    prepare_statement(db_conn, select_self, &self_select);
    prepare_statement(db_conn, select_one_time, &one_time_select);
    prepare_statement(db_conn, select_device_ids, &devices_select);
    prepare_statement(db_conn, select_sessions, &sessions_select);
    prepare_statement(db_conn, select_active, &active_select);

    prepare_statement(db_conn, rowid_insert, &last_rowid_insert);
}

client::database::~database() {
    sqlite3_finalize(self_insert);
    sqlite3_finalize(users_insert);
    sqlite3_finalize(devices_insert);
    sqlite3_finalize(one_time_insert);
    sqlite3_finalize(sessions_insert);

    sqlite3_finalize(users_update);
    sqlite3_finalize(devices_update);
    sqlite3_finalize(devices_update_active);
    sqlite3_finalize(sessions_update);

    sqlite3_finalize(sessions_delete);
    sqlite3_finalize(devices_delete);
    sqlite3_finalize(users_delete);
    sqlite3_finalize(one_time_delete);

    sqlite3_finalize(self_select);
    sqlite3_finalize(one_time_select);
    sqlite3_finalize(devices_select);
    sqlite3_finalize(sessions_select);
    sqlite3_finalize(active_select);

    sqlite3_finalize(last_rowid_insert);

    sqlite3_close(db_conn);
}

void client::database::save_registration(const std::string& email, const int device_id,
        const std::string& auth_token, const crypto::DH_Keypair& identity_keypair,
        const crypto::DH_Keypair& pre_keypair) {
    sqlite3_reset(self_insert);
    sqlite3_clear_bindings(self_insert);

    if (sqlite3_bind_text(self_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_bind_int(self_insert, 2, device_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_bind_text(self_insert, 3, auth_token.c_str(), auth_token.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << identity_keypair;
    }
    auto serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 4, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    ss.str(std::string{});
    {
        boost::archive::text_oarchive arch{ss};
        arch << pre_keypair;
    }
    serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 5, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(self_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::add_one_time(const crypto::DH_Keypair& one_time) {
    sqlite3_reset(one_time_insert);
    sqlite3_clear_bindings(one_time_insert);

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << one_time.get_public();
    }
    auto serialized = ss.str();
    if (sqlite3_bind_blob(
                one_time_insert, 1, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    ss.str(std::string{});
    {
        boost::archive::text_oarchive arch{ss};
        arch << one_time;
    }
    serialized = ss.str();
    if (sqlite3_bind_blob(
                one_time_insert, 2, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(one_time_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::add_user_record(const std::string& email) {
    sqlite3_reset(users_insert);
    sqlite3_clear_bindings(users_insert);

    if (sqlite3_bind_text(users_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(users_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::add_device_record(
        const std::string& email, const int device_index, const crypto::public_key& pub_key) {
    sqlite3_reset(devices_insert);
    sqlite3_clear_bindings(devices_insert);

    if (sqlite3_bind_text(devices_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_bind_int(devices_insert, 2, device_index) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_bind_blob(devices_insert, 3, pub_key.data(), pub_key.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(devices_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

int client::database::add_session(const int device_index, const session& s) {
    sqlite3_reset(sessions_insert);
    sqlite3_clear_bindings(sessions_insert);

    if (sqlite3_bind_int(sessions_insert, 1, device_index) != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << s;
    }
    auto serialized = ss.str();
    if (sqlite3_bind_text(
                sessions_insert, 2, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(sessions_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }

    sqlite3_reset(last_rowid_insert);
    if (sqlite3_step(last_rowid_insert) != SQLITE_ROW) {
        throw_db_error(db_conn);
    }

    int added_session_id = sqlite3_column_int(last_rowid_insert, 0);

    if (sqlite3_step(last_rowid_insert) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }

    return added_session_id;
}

void client::database::mark_user_stale(const std::string& email) {
    sqlite3_reset(users_update);
    sqlite3_clear_bindings(users_update);
    if (sqlite3_bind_text(users_update, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(users_update) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::mark_device_stale(const int device_index) {
    sqlite3_reset(devices_update);
    sqlite3_clear_bindings(devices_update);
    if (sqlite3_bind_int(devices_update, 1, device_index) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(devices_update) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::purge_stale_records() {
    exec_statement(db_conn, delete_users_stale);
    exec_statement(db_conn, delete_devices_stale);
}

void client::database::remove_user_record(const std::string& email) {
    sqlite3_reset(users_delete);
    sqlite3_clear_bindings(users_delete);

    if (sqlite3_bind_text(users_delete, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(users_delete) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::remove_device_record(const int device_index) {
    sqlite3_reset(devices_delete);
    sqlite3_clear_bindings(devices_delete);

    if (sqlite3_bind_int(devices_delete, 1, device_index) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(devices_delete) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::remove_session(const int session_id) {
    sqlite3_reset(sessions_delete);
    sqlite3_clear_bindings(sessions_delete);

    if (sqlite3_bind_int(sessions_delete, 1, session_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(sessions_delete) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::remove_one_time(const crypto::public_key& public_key) {
    sqlite3_reset(one_time_delete);
    sqlite3_clear_bindings(one_time_delete);

    std::stringstream ss;

    {
        boost::archive::text_oarchive arch{ss};
        arch << public_key;
    }

    auto serialized = ss.str();

    if (sqlite3_bind_blob(
                one_time_delete, 1, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(one_time_delete) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

void client::database::activate_session(const int device_index, const int session_id) {
    sqlite3_reset(devices_update_active);
    sqlite3_clear_bindings(devices_update_active);

    if (sqlite3_bind_int(devices_update_active, 1, device_index) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_bind_int(devices_update_active, 2, session_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    if (sqlite3_step(devices_update_active) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}

std::tuple<std::string, int, std::string, crypto::DH_Keypair, crypto::DH_Keypair>
        client::database::get_self_data() {
    sqlite3_reset(self_select);
    sqlite3_clear_bindings(self_select);

    if (sqlite3_step(self_select) != SQLITE_ROW) {
        throw_db_error(db_conn);
    }

    auto user_id = read_db_string(db_conn, self_select, 0);
    const int device_id = sqlite3_column_int(self_select, 1);
    auto auth_token = read_db_string(db_conn, self_select, 2);
    auto identity = read_db_string(db_conn, self_select, 3);
    auto prekey = read_db_string(db_conn, self_select, 4);

    std::stringstream ss{identity};

    crypto::DH_Keypair identity_keypair;
    crypto::DH_Keypair prekey_keypair;

    {
        boost::archive::text_iarchive arch{ss};
        arch >> identity_keypair;
    }
    ss.str(prekey);
    {
        boost::archive::text_iarchive arch{ss};
        arch >> prekey_keypair;
    }

    if (sqlite3_step(self_select) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }

    return {user_id, device_id, auth_token, identity_keypair, prekey_keypair};
}

crypto::DH_Keypair client::database::get_one_time_key(const crypto::public_key& public_key) {
    sqlite3_reset(one_time_select);
    sqlite3_clear_bindings(one_time_select);

    std::stringstream ss;

    {
        boost::archive::text_oarchive arch{ss};
        arch << public_key;
    }

    auto serialized = ss.str();

    if (sqlite3_bind_blob(
                one_time_select, 1, serialized.data(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(one_time_select) != SQLITE_ROW) {
        throw_db_error(db_conn);
    }

    ss.str(read_db_string(db_conn, one_time_select, 0));

    crypto::DH_Keypair one_time_keypair;

    {
        boost::archive::text_iarchive arch{ss};
        arch >> one_time_keypair;
    }

    if (sqlite3_step(one_time_select) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }

    return one_time_keypair;
}

std::vector<int> client::database::get_device_ids(const std::string& email) {
    sqlite3_reset(devices_select);
    sqlite3_clear_bindings(devices_select);

    if (sqlite3_bind_text(devices_select, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    std::vector<int> id_list;

    int err;
    while ((err = sqlite3_step(devices_select)) == SQLITE_ROW) {
        const int id = sqlite3_column_int(devices_select, 0);
        id_list.emplace_back(id);
    }
    if (err != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
    return id_list;
}

std::vector<std::pair<int, session>> client::database::get_sessions_by_device(const int device_id) {
    sqlite3_reset(sessions_select);
    sqlite3_clear_bindings(sessions_select);

    if (sqlite3_bind_int(sessions_select, 1, device_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    std::vector<std::pair<int, session>> session_list;

    int err;
    while ((err = sqlite3_step(sessions_select)) == SQLITE_ROW) {
        const int id = sqlite3_column_int(sessions_select, 0);

        std::stringstream ss{read_db_string(db_conn, sessions_select, 1)};

        //This is annoying but I have to do this for deserialization
        session s{crypto::public_key{}, crypto::DH_Keypair{}, crypto::public_key{}};
        {
            boost::archive::text_iarchive arch{ss};
            arch >> s;
        }
        session_list.emplace_back(id, std::move(s));
    }
    if (err != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
    return session_list;
}

std::pair<int, session> client::database::get_active_session(const int device_id) {
    sqlite3_reset(active_select);
    sqlite3_clear_bindings(active_select);

    if (sqlite3_bind_int(active_select, 1, device_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(active_select) != SQLITE_ROW) {
        throw_db_error(db_conn);
    }

    const int session_id = sqlite3_column_int(active_select, 0);

    std::stringstream ss{read_db_string(db_conn, active_select, 1)};

    //This is annoying but I have to do this for deserialization
    session s{crypto::public_key{}, crypto::DH_Keypair{}, crypto::public_key{}};
    {
        boost::archive::text_iarchive arch{ss};
        arch >> s;
    }

    if (sqlite3_step(active_select) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
    return {session_id, s};
}

void client::database::sync_session(const int session_id, const session& s) {
    sqlite3_reset(sessions_update);
    sqlite3_clear_bindings(sessions_update);

    if (sqlite3_bind_int(sessions_update, 1, session_id) != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    std::stringstream ss;
    boost::archive::text_oarchive arch{ss};
    arch << s;

    const auto serialized = ss.str();

    if (sqlite3_bind_text(
                sessions_update, 2, serialized.data(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }

    if (sqlite3_step(sessions_update) != SQLITE_DONE) {
        throw_db_error(db_conn);
    }
}
