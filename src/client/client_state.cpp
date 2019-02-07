#include <algorithm>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <iterator>
#include <sqlite3.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include "crypto.h"
#include "error.h"
#include "logging.h"
#include "client_state.h"

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

