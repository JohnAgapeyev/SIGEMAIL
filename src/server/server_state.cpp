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
    if (sqlite3_prepare_v2(db_conn, update_pre_key_stmt, strlen(update_pre_key_stmt) + 1, &device_key_update, nullptr) != SQLITE_OK) {
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
    sqlite3_reset(users_insert);
    sqlite3_clear_bindings(users_insert);

    if (sqlite3_bind_text(users_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    const auto trunc_hash = crypto::hash_string(user_id);

    //Store the first 24/32 bytes of the email hash
    if (sqlite3_bind_blob(users_insert, 2, trunc_hash.data(), trunc_hash.size() - 8, SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(users_insert) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_device(const std::string_view user_id, const crypto::public_key& identity,
                const crypto::public_key& pre_key, const crypto::signature& signature) {
    if (!crypto::verify_signed_key(signature, pre_key, identity)) {
        spdlog::get("console")->error("Signature did not verify correctly");
    }

    sqlite3_reset(devices_insert);
    sqlite3_clear_bindings(devices_insert);

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

    if (sqlite3_step(devices_insert) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_one_time_key(const int device_id, const crypto::public_key& one_time) {
    sqlite3_reset(otpk_insert);
    sqlite3_clear_bindings(otpk_insert);

    if (sqlite3_bind_int(otpk_insert, 1, device_id) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_blob(otpk_insert, 2, one_time.data(), one_time.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(otpk_insert) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_message(const int device_id, const std::vector<std::byte>& message_contents) {
    sqlite3_reset(mailbox_insert);
    sqlite3_clear_bindings(mailbox_insert);

    if (sqlite3_bind_int(mailbox_insert, 1, device_id) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_blob(mailbox_insert, 2, message_contents.data(), message_contents.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(mailbox_insert) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_registration_code(const std::string_view email, const int code) {
    sqlite3_reset(registration_codes_insert);
    sqlite3_clear_bindings(registration_codes_insert);

    if (sqlite3_bind_text(registration_codes_insert, 1, email.data(), email.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_int(registration_codes_insert, 2, code) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(registration_codes_insert) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}

void db::database::update_pre_key(const int device_id, const crypto::public_key& pre_key,
                const crypto::signature& signature) {
    //Should check signature validity here, but that requires a subquery, which I'm not implementing yet
    sqlite3_reset(device_key_update);
    sqlite3_clear_bindings(device_key_update);

    if (sqlite3_bind_blob(device_key_update, 1, pre_key.data(), pre_key.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(device_key_update, 2, signature.data(), signature.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_int(device_key_update, 3, device_id) != SQLITE_OK) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(device_key_update) != SQLITE_DONE) {
        spdlog::get("console")->error(sqlite3_errmsg(db_conn));
    }
}
