#include <sqlite3.h>
#include <stdexcept>

#include "crypto.h"
#include "logging.h"
#include "server_state.h"

db::database::database() {
    if (sqlite3_open("foobar_db", &db_conn) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db_conn));
    }

    char* err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::enable_foreign_keys, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }

    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_users, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_devices, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_one_time, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_mailboxes, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }

    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_registration_codes, nullptr, nullptr, &err_msg)) {
        spdlog::get("console")->error(err_msg);
    }

    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_prepare_v2(db_conn, insert_user, strlen(insert_user) + 1, &users_insert, nullptr) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, insert_device, strlen(insert_device) + 1, &devices_insert, nullptr) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, insert_one_time, strlen(insert_one_time) + 1, &otpk_insert, nullptr) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, insert_message, strlen(insert_message) + 1, &mailbox_insert, nullptr) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, insert_registration, strlen(insert_registration) + 1, &registration_codes_insert, nullptr) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

db::database::~database() {
    sqlite3_finalize(users_insert);
    sqlite3_finalize(devices_insert);
    sqlite3_finalize(otpk_insert);
    sqlite3_finalize(mailbox_insert);
    sqlite3_finalize(registration_codes_insert);
    sqlite3_close(db_conn);
}

void db::database::add_user(const std::string_view user_id) {
    if (sqlite3_bind_text(users_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    const auto trunc_hash = crypto::hash_string(user_id);

    //Store the first 24/32 bytes of the email hash
    if (sqlite3_bind_blob(users_insert, 2, trunc_hash.data(), trunc_hash.size() - 8, SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_device(const std::string_view user_id, const crypto::public_key& identity,
                const crypto::public_key& pre_key, const crypto::signature& signature) {
    if (!crypto::verify_signed_key(signature, pre_key, identity)) {
        spdlog::get("console")->error("Signature did not verify correctly");
    }

    if (sqlite3_bind_text(devices_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 2, identity.data(), identity.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 3, pre_key.data(), pre_key.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 4, signature.data(), signature.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}
