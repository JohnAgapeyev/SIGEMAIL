#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <mutex>
#include <sqlite3.h>
#include <string>

#include "crypto.h"
#include "message.h"

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
namespace server {
    class database {
    public:
        database(const char* db_name);
        ~database();
        database(const database&) = delete;
        database(database&&) = default;
        database& operator=(database&&) = default;
        database& operator=(const database&) = delete;

        void add_user(const std::string_view user_id, const std::string_view auth_token);
        //Signature should be verified before this call
        int add_device(const std::string_view user_id, const crypto::public_key& identity,
                const crypto::public_key& pre_key, const crypto::signature& signature);
        void add_one_time_key(const int device_id, const crypto::public_key& one_time);
        void add_message(const std::string_view from_user_id, const std::string_view dest_user_id,
                const int from_device_id, const int dest_device_id,
                const std::vector<std::byte>& message_contents);
        void add_registration_code(const std::string_view email, const int code);

        void update_pre_key(const int device_id, const crypto::public_key& pre_key,
                const crypto::signature& signature);

        void remove_user(const std::string_view user_id);
        void remove_device(const int device_id);
        void remove_one_time_key(const int key_id);
        void remove_message(const int message_id);
        void remove_registration_code(const std::string_view email);

        std::vector<std::array<std::byte, 24>> contact_intersection(
                std::vector<std::array<std::byte, 24>> truncated_hashes);

        [[nodiscard]] bool confirm_auth_token(
                const std::string_view user_id, const std::string_view auth_token);

        std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
                lookup_devices(const std::string_view user_id);
        std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>>
                lookup_devices(const std::vector<int> device_ids);

        std::tuple<int, crypto::public_key> get_one_time_key(const int device_id);

        std::vector<std::tuple<int, std::string, int, int, std::string>> retrieve_messages(
                const std::string_view user_id);

        [[nodiscard]] std::string confirm_registration_code(const int reg_code);

        std::unique_lock<std::mutex> start_transaction();
        void commit_transaction(std::unique_lock<std::mutex>& transaction_lock);
        void rollback_transaction(std::unique_lock<std::mutex>& transaction_lock);

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
        sqlite3_stmt* users_auth_select;

        sqlite3_stmt* devices_user_select;
        sqlite3_stmt* devices_id_select;
        sqlite3_stmt* otpk_select;
        sqlite3_stmt* mailbox_select;
        sqlite3_stmt* registration_codes_select;

        sqlite3_stmt* last_rowid_insert;

        /*
         * I know this could be more efficient by splitting the mutex up for unrelated actions.
         * But my initial implementation which overhauled the sqlite statements failed,
         * so this is the easiest and safest solution at the moment.
         */
        std::mutex db_mut;
        std::mutex transaction_mut;
    };
    static constexpr auto create_users = "\
        CREATE TABLE IF NOT EXISTS users (\
           user_id    TEXT PRIMARY KEY,\
           trunc_hash BLOB NOT NULL UNIQUE,\
           auth_token TEXT NOT NULL UNIQUE\
           CHECK(length(user_id) > 0 and length(auth_token) > 0 and length(trunc_hash) > 0)\
        ) WITHOUT ROWID;";
    static constexpr auto create_devices = "\
        CREATE TABLE IF NOT EXISTS devices (\
           device_id    INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           identity_key BLOB    NOT NULL UNIQUE,\
           pre_key      BLOB    NOT NULL UNIQUE,\
           signature    BLOB    NOT NULL,\
           FOREIGN KEY (user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE\
           CHECK(length(identity_key) > 0 and length(pre_key) > 0 and length(signature) > 0)\
        );";
    static constexpr auto create_one_time = "\
        CREATE TABLE IF NOT EXISTS otpk (\
           key_id       INTEGER PRIMARY KEY,\
           device_id    INTEGER NOT NULL,\
           key          BLOB    NOT NULL UNIQUE,\
           FOREIGN KEY (device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE\
           CHECK(length(key) > 0)\
        );";
    static constexpr auto create_mailboxes = "\
        CREATE TABLE IF NOT EXISTS mailbox (\
           message_id     INTEGER PRIMARY KEY,\
           from_user_id   TEXT    NOT NULL,\
           dest_user_id   TEXT    NOT NULL,\
           from_device_id INTEGER NOT NULL,\
           dest_device_id INTEGER NOT NULL,\
           contents       BLOB    NOT NULL,\
           FOREIGN KEY (from_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY (dest_user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY (from_device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY (dest_device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           CHECK(length(contents) > 0)\
        );";
    static constexpr auto create_registration_codes = "\
        CREATE TABLE IF NOT EXISTS registration_codes (\
           email        TEXT    PRIMARY KEY,\
           code         INTEGER NOT NULL UNIQUE,\
           expiration   TEXT    NOT NULL\
           CHECK(length(email) > 0 and length(expiration) > 0)\
        );";
    static constexpr auto insert_user = "INSERT INTO users VALUES (?1, ?2, ?3);";
    static constexpr auto insert_device
            = "INSERT INTO devices(user_id, identity_key, pre_key, signature) \
                                    VALUES (?1, ?2, ?3, ?4);";
    static constexpr auto insert_one_time = "INSERT INTO otpk(device_id, key) VALUES (?1, ?2);";
    static constexpr auto insert_message
            = "INSERT INTO mailbox(from_user_id, dest_user_id, from_device_id, "
              "dest_device_id, contents) VALUES (?1, ?2, ?3, ?4, ?5);";
    static constexpr auto insert_registration = "INSERT INTO registration_codes VALUES (?1, ?2, "
                                                "strftime('%s', 'now', '+1 day'));";

    static constexpr auto rowid_insert = "SELECT last_insert_rowid();";

    static constexpr auto update_pre_key_stmt
            = "UPDATE devices SET pre_key = ?1, signature = ?2 WHERE device_id = ?3;";

    static constexpr auto delete_user = "DELETE FROM users WHERE user_id = ?1;";
    static constexpr auto delete_device = "DELETE FROM devices WHERE device_id = ?1;";
    static constexpr auto delete_one_time = "DELETE FROM otpk WHERE key_id = ?1;";
    static constexpr auto delete_message = "DELETE FROM mailbox WHERE message_id = ?1;";
    static constexpr auto delete_registration_code
            = "DELETE FROM registration_codes WHERE email = ?1;";

    static constexpr auto select_trunc_hash = "SELECT trunc_hash FROM users;";
    static constexpr auto select_user_auth_token
            = "SELECT auth_token FROM users WHERE user_id = ?1;";
    static constexpr auto select_devices_user_id = "SELECT device_id, identity_key, pre_key, "
                                                   "signature FROM devices WHERE user_id = ?1;";
    static constexpr auto select_devices_device_id = "SELECT device_id, identity_key, pre_key, "
                                                     "signature FROM devices WHERE device_id = ?1;";
    static constexpr auto select_one_time
            = "SELECT key_id, key FROM otpk WHERE device_id = ?1 ORDER BY RANDOM() LIMIT 1;";
    static constexpr auto select_message
            = "SELECT message_id, from_user_id, from_device_id, dest_device_id, "
              "contents FROM mailbox WHERE dest_user_id = ?1;";
    static constexpr auto select_registration
            = "SELECT email, expiration FROM registration_codes WHERE code = ?1;";

    static constexpr auto begin_trans = "BEGIN TRANSACTION";
    static constexpr auto commit_trans = "COMMIT TRANSACTION";
    static constexpr auto rollback_trans = "ROLLBACK TRANSACTION";
} // namespace server

#endif /* end of include guard: SERVER_STATE_H */
