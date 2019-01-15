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
        void add_device(const std::string_view user_id, const crypto::public_key& identity,
                const crypto::public_key& pre_key, const crypto::signature& signature);
        void add_one_time_key(const int device_id, const crypto::public_key& one_time);
        void add_message(const int device_id, const std::vector<std::byte>& message_contents);
        void add_registration_code(const std::string_view email, const int code);

    private:
        sqlite3* db_conn;

        sqlite3_stmt* users_insert;
        sqlite3_stmt* devices_insert;
        sqlite3_stmt* otpk_insert;
        sqlite3_stmt* mailbox_insert;
        sqlite3_stmt* registration_codes_insert;
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
           device_id    INTEGER NOT NULL,\
           contents     BLOB    NOT NULL,\
           FOREIGN KEY (device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE\
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
    constexpr auto insert_message = "INSERT INTO mailbox(device_id, contents) VALUES (?1, ?2);";
    constexpr auto insert_registration = "INSERT INTO registration_codes VALUES (?1, ?2, datetime('now', '+1 month'));";
} // namespace db

#endif /* end of include guard: SERVER_STATE_H */
