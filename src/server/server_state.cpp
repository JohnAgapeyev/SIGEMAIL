#include <algorithm>
#include <iterator>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <utility>

#include "crypto.h"
#include "logging.h"
#include "server_state.h"

db::database::database() {
    if (sqlite3_open("foobar_db", &db_conn) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db_conn));
    }

    char* err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_users, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_devices, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_one_time, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
    }
    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_mailboxes, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
    }

    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_exec(db_conn, db::create_registration_codes, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
    }

    sqlite3_free(err_msg);
    err_msg = nullptr;

    if (sqlite3_prepare_v2(db_conn, insert_user, strlen(insert_user) + 1, &users_insert, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, insert_device, strlen(insert_device) + 1, &devices_insert, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, insert_one_time, strlen(insert_one_time) + 1, &otpk_insert, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, insert_message, strlen(insert_message) + 1, &mailbox_insert, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, insert_registration, strlen(insert_registration) + 1,
                &registration_codes_insert, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, update_pre_key_stmt, strlen(update_pre_key_stmt) + 1,
                &devices_update, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, delete_user, strlen(delete_user) + 1, &users_delete, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, delete_device, strlen(delete_device) + 1, &devices_delete, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, delete_one_time, strlen(delete_one_time) + 1, &otpk_delete, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, delete_message, strlen(delete_message) + 1, &mailbox_delete, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, delete_registration_code, strlen(delete_registration_code) + 1,
                &registration_codes_delete, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, select_trunc_hash, strlen(select_trunc_hash) + 1,
                &users_hash_select, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, select_user_auth_token, strlen(select_user_auth_token) + 1,
                &users_auth_select, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, select_devices_user_id, strlen(select_devices_user_id) + 1,
                &devices_user_select, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(db_conn, select_devices_device_id, strlen(select_devices_device_id) + 1,
                &devices_id_select, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_prepare_v2(
                db_conn, select_one_time, strlen(select_one_time) + 1, &otpk_select, nullptr)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

db::database::~database() {
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
    sqlite3_close(db_conn);
}

void db::database::add_user(const std::string_view user_id, const std::string_view auth_token) {
    sqlite3_reset(users_insert);
    sqlite3_clear_bindings(users_insert);

    if (sqlite3_bind_text(users_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    const auto trunc_hash = crypto::hash_string(user_id);

    //Store the first 24/32 bytes of the email hash
    if (sqlite3_bind_blob(
                users_insert, 2, trunc_hash.data(), trunc_hash.size() - 8, SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_text(users_insert, 3, auth_token.data(), auth_token.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(users_insert) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_device(const std::string_view user_id, const crypto::public_key& identity,
        const crypto::public_key& pre_key, const crypto::signature& signature) {
    sqlite3_reset(devices_insert);
    sqlite3_clear_bindings(devices_insert);

    if (sqlite3_bind_text(devices_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 2, identity.data(), identity.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 3, pre_key.data(), pre_key.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_insert, 4, signature.data(), signature.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(devices_insert) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_one_time_key(const int device_id, const crypto::public_key& one_time) {
    sqlite3_reset(otpk_insert);
    sqlite3_clear_bindings(otpk_insert);

    if (sqlite3_bind_int(otpk_insert, 1, device_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_blob(otpk_insert, 2, one_time.data(), one_time.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(otpk_insert) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_message(const std::string_view user_id, const int device_id,
        const std::vector<std::byte>& message_contents) {
    sqlite3_reset(mailbox_insert);
    sqlite3_clear_bindings(mailbox_insert);

    if (sqlite3_bind_text(mailbox_insert, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_int(mailbox_insert, 2, device_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_blob(mailbox_insert, 3, message_contents.data(), message_contents.size(),
                SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(mailbox_insert) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::add_registration_code(const std::string_view email, const int code) {
    sqlite3_reset(registration_codes_insert);
    sqlite3_clear_bindings(registration_codes_insert);

    if (sqlite3_bind_text(
                registration_codes_insert, 1, email.data(), email.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_int(registration_codes_insert, 2, code) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(registration_codes_insert) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::update_pre_key(const int device_id, const crypto::public_key& pre_key,
        const crypto::signature& signature) {
    sqlite3_reset(devices_update);
    sqlite3_clear_bindings(devices_update);

    if (sqlite3_bind_blob(devices_update, 1, pre_key.data(), pre_key.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
    if (sqlite3_bind_blob(devices_update, 2, signature.data(), signature.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_bind_int(devices_update, 3, device_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(devices_update) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::remove_user(const std::string_view user_id) {
    sqlite3_reset(users_delete);
    sqlite3_clear_bindings(users_delete);

    if (sqlite3_bind_text(users_delete, 1, user_id.data(), user_id.size() + 1, SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(users_delete) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::remove_device(const int device_id) {
    sqlite3_reset(devices_delete);
    sqlite3_clear_bindings(devices_delete);

    if (sqlite3_bind_int(devices_delete, 1, device_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(devices_delete) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::remove_one_time_key(const int key_id) {
    sqlite3_reset(otpk_delete);
    sqlite3_clear_bindings(otpk_delete);

    if (sqlite3_bind_int(otpk_delete, 1, key_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(otpk_delete) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::remove_message(const int message_id) {
    sqlite3_reset(mailbox_delete);
    sqlite3_clear_bindings(mailbox_delete);

    if (sqlite3_bind_int(mailbox_delete, 1, message_id) != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(mailbox_delete) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

void db::database::remove_registration_code(const std::string_view email) {
    sqlite3_reset(registration_codes_delete);
    sqlite3_clear_bindings(registration_codes_delete);

    if (sqlite3_bind_text(
                registration_codes_delete, 1, email.data(), email.size() + 1, SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    if (sqlite3_step(registration_codes_delete) != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }
}

//This is inefficient once the database gets too big due to reallocating the vector, and doing the work outside the database
//Fine for now, but will need attention if scale is ever a factor
std::vector<std::array<std::byte, 24>> db::database::contact_intersection(
        std::vector<std::array<std::byte, 24>> truncated_hashes) {
    std::vector<std::array<std::byte, 24>> all_hashes;
    int err;

    sqlite3_reset(users_hash_select);

    while ((err = sqlite3_step(users_hash_select)) == SQLITE_ROW) {
        std::array<std::byte, 24> trunc_hash;

        const auto db_data = sqlite3_column_blob(users_hash_select, 1);

        //Copy data from database pointer to array
        memcpy(trunc_hash.data(), db_data, 24);

        //Store array into list
        all_hashes.emplace_back(std::move(trunc_hash));
    }

    if (err != SQLITE_DONE) {
        //Statement ended unexpectedly
        spdlog::error(sqlite3_errmsg(db_conn));
        return {};
    }

    std::sort(truncated_hashes.begin(), truncated_hashes.end());
    std::sort(all_hashes.begin(), all_hashes.end());

    std::vector<std::array<std::byte, 24>> intersect;

    std::set_intersection(truncated_hashes.begin(), truncated_hashes.end(), all_hashes.begin(),
            all_hashes.end(), std::make_move_iterator(intersect.end()));

    return intersect;
}

[[nodiscard]] bool db::database::confirm_auth_token(
        const std::string_view user_id, const std::string_view auth_token) {
    sqlite3_reset(users_auth_select);
    sqlite3_clear_bindings(users_auth_select);

    if (sqlite3_bind_text(users_auth_select, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    //User did not exist in the table, or an error happened
    if (sqlite3_step(users_auth_select) != SQLITE_ROW) {
        return false;
    }

    const auto user_token = sqlite3_column_text(users_auth_select, 1);
    const auto user_token_length = sqlite3_column_bytes(users_auth_select, 1);

    return auth_token.compare(std::string_view{reinterpret_cast<const char*>(user_token),
                   static_cast<unsigned long>(user_token_length)})
            == 0;
}

std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
        db::database::lookup_devices(const std::string_view user_id) {
    sqlite3_reset(devices_user_select);
    sqlite3_clear_bindings(devices_user_select);

    if (sqlite3_bind_text(devices_user_select, 1, user_id.data(), user_id.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        spdlog::error(sqlite3_errmsg(db_conn));
    }

    std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> records;

    int err;
    while ((err = sqlite3_step(devices_user_select)) == SQLITE_ROW) {
        auto device_id = sqlite3_column_int(devices_user_select, 1);

        crypto::public_key identity_key;
        const auto idk = sqlite3_column_blob(devices_user_select, 2);
        memcpy(identity_key.data(), idk, identity_key.size());

        crypto::public_key pre_key;
        const auto prk = sqlite3_column_blob(devices_user_select, 3);
        memcpy(pre_key.data(), prk, pre_key.size());

        crypto::signature pre_key_signature;
        const auto pks = sqlite3_column_blob(devices_user_select, 4);
        memcpy(pre_key_signature.data(), pks, pre_key_signature.size());

        records.emplace_back(std::move(device_id), std::move(identity_key), std::move(pre_key),
                std::move(pre_key_signature));
    }
    if (err != SQLITE_DONE) {
        spdlog::error(sqlite3_errmsg(db_conn));
        return {};
    }

    return records;
}

std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
        db::database::lookup_devices(const std::vector<int> device_ids) {
    sqlite3_reset(devices_id_select);
    sqlite3_clear_bindings(devices_id_select);

    std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> records;

    for (const auto id : device_ids) {
        sqlite3_bind_int(devices_id_select, 1, id);

        if (sqlite3_step(devices_id_select) != SQLITE_ROW) {
            spdlog::error(sqlite3_errmsg(db_conn));
            return {};
        }
        auto device_id = sqlite3_column_int(devices_user_select, 1);

        crypto::public_key identity_key;
        const auto idk = sqlite3_column_blob(devices_user_select, 2);
        memcpy(identity_key.data(), idk, identity_key.size());

        crypto::public_key pre_key;
        const auto prk = sqlite3_column_blob(devices_user_select, 3);
        memcpy(pre_key.data(), prk, pre_key.size());

        crypto::signature pre_key_signature;
        const auto pks = sqlite3_column_blob(devices_user_select, 4);
        memcpy(pre_key_signature.data(), pks, pre_key_signature.size());

        records.emplace_back(std::move(device_id), std::move(identity_key), std::move(pre_key),
                std::move(pre_key_signature));

        sqlite3_reset(devices_id_select);
        sqlite3_clear_bindings(devices_id_select);
    }
    return records;
}

crypto::public_key db::database::get_one_time_key(const int device_id) {
    sqlite3_reset(otpk_select);
    sqlite3_clear_bindings(otpk_select);

    sqlite3_bind_int(otpk_select, 1, device_id);

    if (sqlite3_step(otpk_select) != SQLITE_ROW) {
        spdlog::error(sqlite3_errmsg(db_conn));
        return {};
    }

    crypto::public_key output;
    const auto tmp_key = sqlite3_column_blob(otpk_select, 2);

    memcpy(output.data(), tmp_key, output.size());

    return output;
}
