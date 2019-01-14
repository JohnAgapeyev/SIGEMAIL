#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <sqlite3.h>

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

    private:
        sqlite3* db_conn;
    };

    constexpr auto create_users = "\
        CREATE TABLE [IF NOT EXISTS] users (\
           user_id    TEXT PRIMARY KEY,\
           trunc_hash BLOB NOT NULL,\
        ) [WITHOUT ROWID];";
    constexpr auto create_devices = "\
        CREATE TABLE [IF NOT EXISTS] devices (\
           device_id    INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           identity_key BLOB    NOT NULL,\
           pre_key      BLOB    NOT NULL,\
           signature    BLOB    NOT NULL,\
        );";
    constexpr auto create_one_time = "\
        CREATE TABLE [IF NOT EXISTS] otpk (\
           key_id       INTEGER PRIMARY KEY,\
           device_id    INTEGER NOT NULL REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           key          BLOB    NOT NULL,\
        );";
    constexpr auto create_mailboxes = "\
        CREATE TABLE [IF NOT EXISTS] mailbox (\
           message_id   INTEGER PRIMARY KEY,\
           device_id    INTEGER NOT NULL REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           contents     BLOB    NOT NULL,\
        );";
    constexpr auto create_registration_codes = "\
        CREATE TABLE [IF NOT EXISTS] registration_codes (\
           email        TEXT    PRIMARY KEY,\
           code         INTEGER NOT NULL UNIQUE,\
           expiration   TEXT    NOT NULL,\
        );";
} // namespace db

#endif /* end of include guard: SERVER_STATE_H */
