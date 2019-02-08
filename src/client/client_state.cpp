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

#if 0
    prepare_statement(insert_user, &users_insert);
    prepare_statement(insert_device, &devices_insert);
    prepare_statement(insert_one_time, &otpk_insert);
    prepare_statement(insert_message, &mailbox_insert);
    prepare_statement(insert_registration, &registration_codes_insert);

    prepare_statement(update_pre_key_stmt, &devices_update);

    prepare_statement(delete_user, &users_delete);
    prepare_statement(delete_device, &devices_delete);
    prepare_statement(delete_one_time, &otpk_delete);
    prepare_statement(delete_message, &mailbox_delete);
    prepare_statement(delete_registration_code, &registration_codes_delete);

    prepare_statement(select_trunc_hash, &users_hash_select);
    prepare_statement(select_user_auth_token, &users_auth_select);
    prepare_statement(select_devices_user_id, &devices_user_select);
    prepare_statement(select_devices_device_id, &devices_id_select);
    prepare_statement(select_one_time, &otpk_select);
    prepare_statement(select_message, &mailbox_select);
    prepare_statement(select_registration, &registration_codes_select);
#endif
}

client::db::database::~database() {
    sqlite3_finalize(self_insert);
    sqlite3_finalize(users_insert);
    sqlite3_finalize(devices_insert);
    sqlite3_finalize(one_time_insert);
    sqlite3_finalize(sessions_insert);
    sqlite3_finalize(users_update);
    sqlite3_finalize(devices_update);
#if 0
    sqlite3_finalize(users_insert);
    sqlite3_finalize(devices_insert);
    sqlite3_finalize(otpk_insert);
    sqlite3_finalize(mailbox_insert);
    sqlite3_finalize(registration_codes_insert);
    sqlite3_finalize(devices_update);
    sqlite3_finalize(users_delete);
    sqlite3_finalize(devices_delete);
    sqlite3_finalize(otpk_delete);
    sqlite3_finalize(mailbox_delete);
    sqlite3_finalize(registration_codes_delete);
    sqlite3_finalize(users_hash_select);
    sqlite3_finalize(users_auth_select);
    sqlite3_finalize(devices_id_select);
    sqlite3_finalize(devices_user_select);
    sqlite3_finalize(otpk_select);
    sqlite3_finalize(mailbox_select);
    sqlite3_finalize(registration_codes_select);
#endif
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

    if (sqlite3_step(self_insert) != SQLITE_OK) {
        throw_db_error();
    }
}

void client::db::database::add_one_time(const crypto::DH_Keypair& one_time) {
    sqlite3_reset(one_time_insert);
    sqlite3_clear_bindings(one_time_insert);

    std::stringstream ss;
    {
        boost::archive::text_oarchive arch{ss};
        arch << one_time;
    }
    auto serialized = ss.str();

    if (sqlite3_bind_blob(self_insert, 1, serialized.c_str(), serialized.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(one_time_insert) != SQLITE_OK) {
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
    if (sqlite3_step(users_insert) != SQLITE_OK) {
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
    if (sqlite3_step(devices_insert) != SQLITE_OK) {
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

    if (sqlite3_step(sessions_insert) != SQLITE_OK) {
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
    if (sqlite3_step(users_update) != SQLITE_OK) {
        throw_db_error();
    }
}

void client::db::database::mark_device_stale(const int device_index) {
    sqlite3_reset(devices_update);
    sqlite3_clear_bindings(devices_update);
    if (sqlite3_bind_int(devices_update, 1, device_index) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_update) != SQLITE_OK) {
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
    if (sqlite3_step(users_delete) != SQLITE_OK) {
        throw_db_error();
    }
}

void client::db::database::remove_device_record(const int device_index) {
    sqlite3_reset(devices_delete);
    sqlite3_clear_bindings(devices_delete);

    if (sqlite3_bind_int(devices_delete, 1, device_index) != SQLITE_OK) {
        throw_db_error();
    }
    if (sqlite3_step(devices_delete) != SQLITE_OK) {
        throw_db_error();
    }
}

#if 0
void client::db::database::remove_session(
        const std::string& email, const int device_index, const session& s) {
    //
}
#endif
