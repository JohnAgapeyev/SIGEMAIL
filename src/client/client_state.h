#ifndef SERVER_STATE_H
#define SERVER_STATE_H

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
namespace client::db {
    class database {
    public:
        database(const char *db_name);
        ~database();
        database(const database&) = delete;
        database(database&&) = default;
        database& operator=(database&&) = default;
        database& operator=(const database&) = delete;

        void add_user(const std::string_view user_id, const std::string_view auth_token);
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

        [[nodiscard]] bool confirm_auth_token(const std::string_view user_id, const std::string_view auth_token);

        std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> lookup_devices(const std::string_view user_id);
        std::vector<std::tuple<int, crypto::public_key, crypto::public_key, crypto::signature>> lookup_devices(const std::vector<int> device_ids);

        std::tuple<int, crypto::public_key> get_one_time_key(const int device_id);

        std::vector<std::tuple<int, int, std::string>> retrieve_messages(const std::string_view user_id);

        [[nodiscard]] std::string confirm_registration_code(const int reg_code);

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

        void prepare_statement(const char *sql, sqlite3_stmt **stmt);
        void exec_statement(const char *sql);
        void throw_db_error();
    };

    constexpr auto IN_MEMORY_DB = ":memory:";

    constexpr auto create_devices = "\
        CREATE TABLE IF NOT EXISTS devices (\
           device_id    INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           identity_key BLOB    NOT NULL UNIQUE,\
           pre_key      BLOB    NOT NULL UNIQUE,\
           signature    BLOB    NOT NULL,\
           FOREIGN KEY (user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE\
           CHECK(length(identity_key) > 0 and length(pre_key) > 0 and length(signature) > 0)\
        );";
    constexpr auto insert_device = "INSERT INTO devices(user_id, identity_key, pre_key, signature) \
                                    VALUES (?1, ?2, ?3, ?4);";

    constexpr auto update_pre_key_stmt
            = "UPDATE devices SET pre_key = ?1, signature = ?2 WHERE device_id = ?3;";

    constexpr auto delete_user = "DELETE FROM users WHERE user_id = ?1;";

    constexpr auto select_devices_user_id = "SELECT device_id, identity_key, pre_key, signature FROM devices WHERE user_id = ?1;";
} // namespace db

#endif /* end of include guard: SERVER_STATE_H */
