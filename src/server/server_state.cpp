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
#include "db_utils.h"
#include "error.h"
#include "logging.h"
#include "server_state.h"

server::database::database(const char* db_name) :
        users_insert(db_conn, insert_user), devices_insert(db_conn, insert_device),
        otpk_insert(db_conn, insert_one_time), mailbox_insert(db_conn, insert_message),
        registration_codes_insert(db_conn, insert_registration),
        devices_update(db_conn, update_pre_key_stmt), users_delete(db_conn, delete_user),
        devices_delete(db_conn, delete_device), otpk_delete(db_conn, delete_one_time),
        mailbox_delete(db_conn, delete_message),
        registration_codes_delete(db_conn, delete_registration_code),
        users_hash_select(db_conn, select_trunc_hash),
        users_auth_select(db_conn, select_user_auth_token),
        devices_user_select(db_conn, select_devices_user_id),
        devices_id_select(db_conn, select_devices_device_id), otpk_select(db_conn, select_one_time),
        mailbox_select(db_conn, select_message),
        registration_codes_select(db_conn, select_registration),
        last_rowid_insert(db_conn, rowid_insert) {
    if (sqlite3_open(db_name, &db_conn) != SQLITE_OK) {
        throw db_error(sqlite3_errmsg(db_conn));
    }
    exec_statement(db_conn, create_users);
    exec_statement(db_conn, create_devices);
    exec_statement(db_conn, create_one_time);
    exec_statement(db_conn, create_mailboxes);
    exec_statement(db_conn, create_registration_codes);
}

server::database::~database() {
    sqlite3_close(db_conn);
}

void server::database::add_user(const std::string_view user_id, const std::string_view auth_token) {
    const auto hash = crypto::hash_string(user_id);
    std::array<std::byte, 24> trunc_hash;
    std::copy(hash.begin(), hash.begin() + 24, trunc_hash.begin());

    users_insert.bind_text(1, user_id);
    users_insert.bind_blob(2, trunc_hash.data(), trunc_hash.size());
    users_insert.bind_text(3, auth_token);
    users_insert.execute_done();
}

int server::database::add_device(const std::string_view user_id, const crypto::public_key& identity,
        const crypto::public_key& pre_key, const crypto::signature& signature) {
    devices_insert.bind_text(1, user_id);
    devices_insert.bind_blob(2, identity.data(), identity.size());
    devices_insert.bind_blob(3, pre_key.data(), pre_key.size());
    devices_insert.bind_blob(4, signature.data(), signature.size());

    devices_insert.execute_done();

    if (!last_rowid_insert.execute_row()) {
        throw_db_error(db_conn);
    }

    int inserted_device_id = last_rowid_insert.column_int(0);

    last_rowid_insert.execute_done();

    return inserted_device_id;
}

void server::database::add_one_time_key(const int device_id, const crypto::public_key& one_time) {
    otpk_insert.bind_int(1, device_id);
    otpk_insert.bind_blob(2, one_time.data(), one_time.size());
    otpk_insert.execute_done();
}

void server::database::add_message(const std::string_view from_user_id,
        const std::string_view dest_user_id, const int from_device_id, const int dest_device_id,
        const std::vector<std::byte>& message_contents) {
    mailbox_insert.bind_text(1, from_user_id);
    mailbox_insert.bind_text(2, dest_user_id);
    mailbox_insert.bind_int(3, from_device_id);
    mailbox_insert.bind_int(4, dest_device_id);
    mailbox_insert.bind_blob(5, message_contents.data(), message_contents.size());
    mailbox_insert.execute_done();
}

void server::database::add_registration_code(const std::string_view email, const int code) {
    registration_codes_insert.bind_text(1, email);
    registration_codes_insert.bind_int(2, code);
    registration_codes_insert.execute_done();
}

void server::database::update_pre_key(const int device_id, const crypto::public_key& pre_key,
        const crypto::signature& signature) {
    devices_insert.bind_blob(1, pre_key.data(), pre_key.size());
    devices_insert.bind_blob(2, signature.data(), signature.size());
    devices_insert.bind_int(3, device_id);
    devices_insert.execute_done();
}

void server::database::remove_user(const std::string_view user_id) {
    users_delete.bind_text(1, user_id);
    users_delete.execute_done();
}

void server::database::remove_device(const int device_id) {
    devices_delete.bind_int(1, device_id);
    devices_delete.execute_done();
}

void server::database::remove_one_time_key(const int key_id) {
    otpk_delete.bind_int(1, key_id);
    otpk_delete.execute_done();
}

void server::database::remove_message(const int message_id) {
    mailbox_delete.bind_int(1, message_id);
    mailbox_delete.execute_done();
}

void server::database::remove_registration_code(const std::string_view email) {
    registration_codes_delete.bind_text(1, email);
    registration_codes_delete.execute_done();
}

//This is inefficient once the database gets too big due to reallocating the vector, and doing the work outside the database
//Fine for now, but will need attention if scale is ever a factor
std::vector<std::array<std::byte, 24>> server::database::contact_intersection(
        std::vector<std::array<std::byte, 24>> truncated_hashes) {
    std::vector<std::array<std::byte, 24>> all_hashes;

    while (users_hash_select.execute_row()) {
        std::array<std::byte, 24> trunc_hash;

        const auto db_data = users_hash_select.column_blob(0);

        //Copy data from database pointer to array
        std::copy_n(db_data.begin(), 24, trunc_hash.begin());

        //Store array into list
        all_hashes.emplace_back(std::move(trunc_hash));
    }

    std::sort(truncated_hashes.begin(), truncated_hashes.end());
    std::sort(all_hashes.begin(), all_hashes.end());

    std::vector<std::array<std::byte, 24>> intersect;

    std::set_intersection(truncated_hashes.begin(), truncated_hashes.end(), all_hashes.begin(),
            all_hashes.end(), std::back_inserter(intersect));

    return intersect;
}

[[nodiscard]] bool server::database::confirm_auth_token(
        const std::string_view user_id, const std::string_view auth_token) {
    users_auth_select.bind_text(1, user_id);

    //User did not exist in the table
    if (!users_auth_select.execute_row()) {
        return false;
    }

    const auto user_token = users_auth_select.column_text(0);
    return user_token == auth_token;
}

std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
        server::database::lookup_devices(const std::string_view user_id) {
    devices_user_select.bind_text(1, user_id);

    std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> records;

    while (devices_user_select.execute_row()) {
        auto device_id = devices_user_select.column_int(0);

        crypto::public_key identity_key;
        const auto idk = devices_user_select.column_blob(1);
        std::copy_n(idk.begin(), identity_key.size(), identity_key.begin());

        crypto::public_key pre_key;
        const auto prk = devices_user_select.column_blob(2);
        std::copy_n(prk.begin(), pre_key.size(), pre_key.begin());

        crypto::signature pre_key_signature;
        const auto pks = devices_user_select.column_blob(3);
        std::copy_n(pks.begin(), pre_key_signature.size(), pre_key_signature.begin());

        records.emplace_back(std::move(device_id), std::move(identity_key), std::move(pre_key),
                std::move(pre_key_signature));
    }
    return records;
}

std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
        server::database::lookup_devices(const std::vector<int> device_ids) {
    std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> records;

    for (const auto id : device_ids) {
        devices_id_select.bind_int(1, id);
        if (!devices_id_select.execute_row()) {
            throw_db_error(db_conn);
        }

        auto device_id = devices_id_select.column_int(0);
        if (device_id != id) {
            throw_db_error(db_conn);
        }

        crypto::public_key identity_key;
        const auto idk = devices_id_select.column_blob(1);
        std::copy_n(idk.begin(), identity_key.size(), identity_key.begin());

        crypto::public_key pre_key;
        const auto prk = devices_id_select.column_blob(2);
        std::copy_n(prk.begin(), pre_key.size(), pre_key.begin());

        crypto::signature pre_key_signature;
        const auto pks = devices_id_select.column_blob(3);
        std::copy_n(pks.begin(), pre_key_signature.size(), pre_key_signature.begin());

        records.emplace_back(std::move(device_id), std::move(identity_key), std::move(pre_key),
                std::move(pre_key_signature));

        //Make sure there aren't any more expected rows
        devices_id_select.execute_done();
    }
    return records;
}

std::tuple<int, crypto::public_key> server::database::get_one_time_key(const int device_id) {
    otpk_select.bind_int(1, device_id);

    if (!otpk_select.execute_row()) {
        throw_db_error(db_conn);
    }

    const auto key_id = otpk_select.column_int(0);

    crypto::public_key output;
    const auto tmp_key = otpk_select.column_blob(1);
    std::copy_n(tmp_key.begin(), output.size(), output.begin());

    //Ensure the statement finishes and only has the one expected result
    otpk_select.execute_done();

    return {std::move(key_id), std::move(output)};
}

std::vector<std::tuple<int, std::string, int, int, std::string>>
        server::database::retrieve_messages(const std::string_view user_id) {
    std::vector<std::tuple<int, std::string, int, int, std::string>> records;

    mailbox_select.bind_text(1, user_id);

    while (mailbox_select.execute_row()) {
        const auto message_id = mailbox_select.column_int(0);
        const auto from_user_id = mailbox_select.column_text(1);
        const auto from_device_id = mailbox_select.column_int(2);
        const auto dest_device_id = mailbox_select.column_int(3);
        const auto m_data = mailbox_select.column_text(4);

        records.emplace_back(std::move(message_id), std::move(from_user_id),
                std::move(from_device_id), std::move(dest_device_id), std::move(m_data));
    }

    return records;
}

[[nodiscard]] std::string server::database::confirm_registration_code(const int reg_code) {
    registration_codes_select.bind_int(1, reg_code);
    if (!registration_codes_select.execute_row()) {
        //No rows
        return "";
    }

    const auto email = registration_codes_select.column_text(0);
    const auto date = registration_codes_select.column_text(1);

    uint64_t date_int;
    try {
        date_int = std::stoi(date);
    } catch (...) {
        throw_db_error(db_conn);
    }
    const uint64_t curr_time = std::time(nullptr);

    if (date_int < curr_time) {
        //Registration code has expired
        remove_registration_code(email);
        return "";
    }

    //Make sure there aren't any more expected rows
    registration_codes_select.execute_done();

    return email;
}
