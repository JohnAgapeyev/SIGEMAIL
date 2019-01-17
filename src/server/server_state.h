#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <sqlite3.h>
#include <string>

#include "crypto.h"

/**
 * DATABASE SCHEMA
 * Need the following tables:
 *  Users
 *      User ID (email address aka TEXT) PRIMARY KEY
 *      Truncated hash (BLOB for contact intersection)
 *  Devices
 *      User ID (email address aka TEXT) PRIMARY KEY FOREIGN KEY
 *      Device ID (uint64_t) PRIMARY KEY
 *      Identity Public Key (BLOB)
 *      Pre Key (BLOB)
 *      Pre Key Signature (BLOB)
 *  One Time Pre Keys
 *      User ID (email address aka TEXT) PRIMARY KEY FOREIGN KEY
 *      Device ID (uint64_t) PRIMARY KEY FOREIGN KEY
 *      One Time Public Key (BLOB)
 *  Messages
 *      User ID (email address) PRMIARY KEY FOREIGN KEY
 *      Device ID (uint64_t) PRIMARY KEY FOREIGN KEY
 *      Message Contents (BLOB)
 *  Registration Codes
 *      Email address PRIMARY KEY
 *      Code (BLOB)
 *      Expiration Timestamp (TEXT)
 */
namespace db {
    class database {
    public:
        database();
        ~database();
        database(const database&) = delete;
        database(database&&) = default;
        database& operator=(database&&) = default;
        database& operator=(const database&) = delete;

        void add_user(const std::string_view user_id);
        //Signature should be verified before this call
        void add_device(const std::string_view user_id, const crypto::public_key& identity,
                const crypto::public_key& pre_key, const crypto::signature& signature);
        void add_one_time_key(const int device_id, const crypto::public_key& one_time);
        void add_message(const std::string_view user_id, const int device_id, const std::vector<std::byte>& message_contents);
        void add_registration_code(const std::string_view email, const int code);

        void update_pre_key(const int device_id, const crypto::public_key& pre_key,
                const crypto::signature& signature);

        void remove_user(const std::string_view user_id);
        void remove_device(const int device_id);
        void remove_one_time_key(const int key_id);
        void remove_message(const int message_id);
        void remove_registration_code(const std::string_view email);

        std::vector<std::array<std::byte, 24>> contact_intersection(std::vector<std::array<std::byte, 24>> truncated_hashes);

    private:
        sqlite3* db_conn;

        sqlite3_stmt* users_insert;
        sqlite3_stmt* devices_insert;
        sqlite3_stmt* otpk_insert;
        sqlite3_stmt* mailbox_insert;
        sqlite3_stmt* registration_codes_insert;

        sqlite3_stmt* devices_update;

        sqlite3_stmt* users_delete;
        sqlite3_stmt* devices_delete;
        sqlite3_stmt* otpk_delete;
        sqlite3_stmt* mailbox_delete;
        sqlite3_stmt* registration_codes_delete;

        sqlite3_stmt* users_hash_select;
    };

    constexpr auto create_users = "\
        CREATE TABLE IF NOT EXISTS users (\
           user_id    TEXT PRIMARY KEY,\
           trunc_hash BLOB NOT NULL UNIQUE\
        ) WITHOUT ROWID;";
    constexpr auto create_devices = "\
        CREATE TABLE IF NOT EXISTS devices (\
           device_id    INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           identity_key BLOB    NOT NULL UNIQUE,\
           pre_key      BLOB    NOT NULL UNIQUE,\
           signature    BLOB    NOT NULL,\
           FOREIGN KEY (user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE\
        );";
    constexpr auto create_one_time = "\
        CREATE TABLE IF NOT EXISTS otpk (\
           key_id       INTEGER PRIMARY KEY,\
           device_id    INTEGER NOT NULL,\
           key          BLOB    NOT NULL UNIQUE,\
           FOREIGN KEY (device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE\
        );";
    constexpr auto create_mailboxes = "\
        CREATE TABLE IF NOT EXISTS mailbox (\
           message_id   INTEGER PRIMARY KEY,\
           user_id      TEXT NOT NULL,\
           device_id    INTEGER NOT NULL,\
           contents     BLOB    NOT NULL,\
           FOREIGN KEY (device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY (user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE\
        );";
    constexpr auto create_registration_codes = "\
        CREATE TABLE IF NOT EXISTS registration_codes (\
           email        TEXT    PRIMARY KEY,\
           code         INTEGER NOT NULL UNIQUE,\
           expiration   TEXT    NOT NULL\
        );";
    constexpr auto insert_user = "INSERT INTO users VALUES (?1, ?2);";
    constexpr auto insert_device = "INSERT INTO devices(user_id, identity_key, pre_key, signature) \
                                    VALUES (?1, ?2, ?3, ?4);";
    constexpr auto insert_one_time = "INSERT INTO otpk(device_id, key) VALUES (?1, ?2);";
    constexpr auto insert_message = "INSERT INTO mailbox(user_id, device_id, contents) VALUES (?1, ?2, ?3);";
    constexpr auto insert_registration
            = "INSERT INTO registration_codes VALUES (?1, ?2, datetime('now', '+1 day'));";

    constexpr auto update_pre_key_stmt
            = "UPDATE devices SET pre_key = ?1, signature = ?2 WHERE device_id = ?3;";

    constexpr auto delete_user = "DELETE FROM users WHERE user_id = ?1;";
    constexpr auto delete_device = "DELETE FROM devices WHERE device_id = ?1;";
    constexpr auto delete_one_time = "DELETE FROM otpk WHERE key_id = ?1;";
    constexpr auto delete_message = "DELETE FROM mailbox WHERE message_id = ?1;";
    constexpr auto delete_registration_code = "DELETE FROM registration_codes WHERE email = ?1;";

    constexpr auto select_trunc_hash = "SELECT trunc_hash FROM users;";
} // namespace db

#endif /* end of include guard: SERVER_STATE_H */
