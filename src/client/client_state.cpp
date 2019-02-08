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
#include "error.h"
#include "logging.h"

void client::db::database::prepare_statement(const char* sql, sqlite3_stmt** stmt) {
    if (sqlite3_prepare_v2(db_conn, sql, strlen(sql) + 1, stmt, nullptr) != SQLITE_OK) {
        throw_db_error();
    }
}

void client::db::database::exec_statement(const char* sql) {
    char* err_msg = nullptr;

    if (sqlite3_exec(db_conn, sql, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
        throw db_error(err_msg);
    }
    sqlite3_free(err_msg);
}

void client::db::database::throw_db_error() {
    const auto err_msg = sqlite3_errmsg(db_conn);
    spdlog::error(err_msg);
    throw db_error(err_msg);
}

client::db::database::database(const char* db_name) {
    if (sqlite3_open(db_name, &db_conn) != SQLITE_OK) {
        throw db_error(sqlite3_errmsg(db_conn));
    }

    exec_statement(create_self);
    exec_statement(create_users);
    exec_statement(create_devices);
    exec_statement(create_one_time);
    exec_statement(create_sessions);

    prepare_statement(insert_self, &self_insert);
    prepare_statement(insert_users, &users_insert);
    prepare_statement(insert_devices, &devices_insert);
    prepare_statement(insert_one_time, &one_time_insert);
    prepare_statement(insert_sessions, &sessions_insert);

    prepare_statement(update_users, &users_update);
    prepare_statement(update_devices, &devices_update);
    prepare_statement(update_devices_active, &devices_update_active);

    prepare_statement(delete_sessions, &sessions_delete);
    prepare_statement(delete_users, &users_delete);
    prepare_statement(delete_one_time, &one_time_delete);
    prepare_statement(delete_devices, &devices_delete);

    prepare_statement(select_self, &self_select);
    prepare_statement(select_one_time, &one_time_select);
    prepare_statement(select_device_ids, &devices_select);
    prepare_statement(select_sessions, &sessions_select);
}

client::db::database::~database() {
    sqlite3_finalize(self_insert);
    sqlite3_finalize(users_insert);
    sqlite3_finalize(devices_insert);
    sqlite3_finalize(one_time_insert);
    sqlite3_finalize(sessions_insert);

    sqlite3_finalize(users_update);
    sqlite3_finalize(devices_update);
    sqlite3_finalize(devices_update_active);

    sqlite3_finalize(sessions_delete);
    sqlite3_finalize(devices_delete);
    sqlite3_finalize(users_delete);
    sqlite3_finalize(one_time_delete);

    sqlite3_finalize(self_select);
    sqlite3_finalize(one_time_select);
    sqlite3_finalize(devices_select);
    sqlite3_finalize(sessions_select);

    sqlite3_close(db_conn);
}

void client::db::database::save_registration(const std::string& email, const int device_id,
        const std::string& auth_token, const crypto::DH_Keypair& identity_keypair,
        const crypto::DH_Keypair& pre_keypair) {
    sqlite3_reset(self_insert);
    sqlite3_clear_bindings(self_insert);

    if (sqlite3_bind_text(self_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_bind_int(self_insert, 2, device_id) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_bind_text(self_insert, 3, auth_token.c_str(), auth_token.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << identity_keypair;
    }
    auto serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 4, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    ss.str(std::string{});
    {
        boost::archive::text_oarchive arch{ss};
        arch << pre_keypair;
    }
    serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 5, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }

    if (sqlite3_step(self_insert) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::add_one_time(const crypto::DH_Keypair& one_time) {
    sqlite3_reset(one_time_insert);
    sqlite3_clear_bindings(one_time_insert);

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << one_time.get_public();
    }
    auto serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 1, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    ss.str(std::string{});
    {
        boost::archive::text_oarchive arch{ss};
        arch << one_time;
    }
    serialized = ss.str();
    if (sqlite3_bind_blob(self_insert, 2, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(one_time_insert) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::add_user_record(const std::string& email) {
    sqlite3_reset(users_insert);
    sqlite3_clear_bindings(users_insert);

    if (sqlite3_bind_text(users_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(users_insert) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::add_device_record(const std::string& email) {
    sqlite3_reset(devices_insert);
    sqlite3_clear_bindings(devices_insert);

    if (sqlite3_bind_text(devices_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_insert) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::add_session(
        const std::string& email, const int device_index, const session& s) {
    sqlite3_reset(sessions_insert);
    sqlite3_clear_bindings(sessions_insert);

    if (sqlite3_bind_text(sessions_insert, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_bind_int(sessions_insert, 2, device_index) != SQLITE_OK) {
        throw_db_error();
    }

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << s;
    }
    auto serialized = ss.str();
    if (sqlite3_bind_text(
                sessions_insert, 3, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }

    if (sqlite3_step(sessions_insert) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::mark_user_stale(const std::string& email) {
    sqlite3_reset(users_update);
    sqlite3_clear_bindings(users_update);
    if (sqlite3_bind_text(users_update, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(users_update) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::mark_device_stale(const int device_index) {
    sqlite3_reset(devices_update);
    sqlite3_clear_bindings(devices_update);
    if (sqlite3_bind_int(devices_update, 1, device_index) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_update) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::purge_stale_records() {
    exec_statement(delete_users_stale);
    exec_statement(delete_devices_stale);
}

void client::db::database::remove_user_record(const std::string& email) {
    sqlite3_reset(users_delete);
    sqlite3_clear_bindings(users_delete);

    if (sqlite3_bind_text(users_delete, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(users_delete) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::remove_device_record(const int device_index) {
    sqlite3_reset(devices_delete);
    sqlite3_clear_bindings(devices_delete);

    if (sqlite3_bind_int(devices_delete, 1, device_index) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_delete) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::remove_session(const int session_id) {
    sqlite3_reset(sessions_delete);
    sqlite3_clear_bindings(sessions_delete);

    if (sqlite3_bind_int(sessions_delete, 1, session_id) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(sessions_delete) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::remove_one_time(const crypto::public_key& public_key) {
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
        throw_db_error();
    }

    if (sqlite3_step(one_time_delete) != SQLITE_DONE) {
        throw_db_error();
    }
}

void client::db::database::activate_session(const int device_index, const int session_id) {
    sqlite3_reset(devices_update_active);
    sqlite3_clear_bindings(devices_update_active);

    if (sqlite3_bind_int(devices_update_active, 1, device_index) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_bind_int(devices_update_active, 2, session_id) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_update_active) != SQLITE_DONE) {
        throw_db_error();
    }
}

std::tuple<std::string, int, std::string, crypto::DH_Keypair, crypto::DH_Keypair>
        client::db::database::get_self_data() {
    sqlite3_reset(self_select);
    sqlite3_clear_bindings(self_select);

    if (sqlite3_step(self_select) != SQLITE_ROW) {
        throw_db_error();
    }

    const auto user_id_str = sqlite3_column_text(self_select, 0);
    if (!user_id_str) {
        throw_db_error();
    }

    const int user_id_len = sqlite3_column_bytes(self_select, 0);

    std::string user_id{
            reinterpret_cast<const char*>(user_id_str), static_cast<unsigned long>(user_id_len)};

    const int device_id = sqlite3_column_int(self_select, 1);

    const auto auth_token_str = sqlite3_column_int(self_select, 2);
    if (!auth_token_str) {
        throw_db_error();
    }

    const int auth_token_len = sqlite3_column_bytes(self_select, 2);

    std::string auth_token{reinterpret_cast<const char*>(auth_token_str),
            static_cast<unsigned long>(auth_token_len)};

    const auto identity_str = sqlite3_column_int(self_select, 3);
    if (!identity_str) {
        throw_db_error();
    }

    const int identity_str_len = sqlite3_column_bytes(self_select, 3);

    std::string identity{reinterpret_cast<const char*>(identity_str),
            static_cast<unsigned long>(identity_str_len)};

    const auto prekey_str = sqlite3_column_int(self_select, 3);
    if (!prekey_str) {
        throw_db_error();
    }

    const int prekey_str_len = sqlite3_column_bytes(self_select, 3);

    std::string prekey{
            reinterpret_cast<const char*>(prekey_str), static_cast<unsigned long>(prekey_str_len)};

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
        throw_db_error();
    }

    return {user_id, device_id, auth_token, identity_keypair, prekey_keypair};
}

crypto::DH_Keypair client::db::database::get_one_time_key(const crypto::public_key& public_key) {
    sqlite3_reset(one_time_select);
    sqlite3_clear_bindings(one_time_select);

    if (sqlite3_bind_blob(
                one_time_select, 1, public_key.data(), public_key.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }

    if (sqlite3_step(one_time_select) != SQLITE_ROW) {
        throw_db_error();
    }

    const auto serialized_str = sqlite3_column_text(self_select, 0);
    if (!serialized_str) {
        throw_db_error();
    }
    const auto serialized_len = sqlite3_column_bytes(self_select, 0);

    std::stringstream ss{std::string{reinterpret_cast<const char*>(serialized_str),
            static_cast<unsigned long>(serialized_len)}};

    crypto::DH_Keypair one_time_keypair;

    {
        boost::archive::text_iarchive arch{ss};
        arch >> one_time_keypair;
    }

    return one_time_keypair;
}

std::vector<int> client::db::database::get_device_ids(const std::string& email) {
    sqlite3_reset(devices_select);
    sqlite3_clear_bindings(devices_select);

    if (sqlite3_bind_text(devices_select, 1, email.c_str(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }

    std::vector<int> id_list;

    int err;
    while ((err = sqlite3_step(devices_select)) == SQLITE_ROW) {
        const int id = sqlite3_column_int(devices_select, 0);
        id_list.emplace_back(id);
    }
    if (err != SQLITE_DONE) {
        throw_db_error();
    }
    return id_list;
}

std::vector<std::pair<int, session>> client::db::database::get_sessions_by_device(
        const int device_id) {
    sqlite3_reset(sessions_select);
    sqlite3_clear_bindings(sessions_select);

    if (sqlite3_bind_int(sessions_select, 1, device_id) != SQLITE_OK) {
        throw_db_error();
    }

    std::vector<std::pair<int, session>> session_list;

    int err;
    while ((err = sqlite3_step(sessions_select)) == SQLITE_ROW) {
        const int id = sqlite3_column_int(sessions_select, 0);
        const auto serialized_str = sqlite3_column_text(self_select, 1);
        if (!serialized_str) {
            throw_db_error();
        }
        const auto serialized_len = sqlite3_column_bytes(self_select, 1);

        std::stringstream ss{std::string{reinterpret_cast<const char*>(serialized_str),
                static_cast<unsigned long>(serialized_len)}};

        //This is annoying but I have to do this for deserialization
        session s{crypto::public_key{}, crypto::DH_Keypair{}};
        {
            boost::archive::text_iarchive arch{ss};
            arch >> s;
        }
        session_list.emplace_back(id, std::move(s));
    }
    if (err != SQLITE_DONE) {
        throw_db_error();
    }
    return session_list;
}

session client::db::database::get_active_session(const int device_id) {
    sqlite3_reset(active_select);
    sqlite3_clear_bindings(active_select);

    if (sqlite3_bind_int(active_select, 1, device_id) != SQLITE_OK) {
        throw_db_error();
    }

    if (sqlite3_step(active_select) != SQLITE_ROW) {
        throw_db_error();
    }

    const auto serialized_str = sqlite3_column_text(self_select, 0);
    if (!serialized_str) {
        throw_db_error();
    }
    const auto serialized_len = sqlite3_column_bytes(self_select, 0);

    std::stringstream ss{std::string{reinterpret_cast<const char*>(serialized_str),
            static_cast<unsigned long>(serialized_len)}};

    //This is annoying but I have to do this for deserialization
    session s{crypto::public_key{}, crypto::DH_Keypair{}};
    {
        boost::archive::text_iarchive arch{ss};
        arch >> s;
    }

    if (sqlite3_step(active_select) != SQLITE_DONE) {
        throw_db_error();
    }
    return s;
}
