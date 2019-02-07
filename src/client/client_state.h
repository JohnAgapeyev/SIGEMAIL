#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <sqlite3.h>
#include <string>

#include "crypto.h"
#include "message.h"
#include "session.h"

/**
 * DATABASE SCHEMA
 * Need the following tables:
 * Self
 *      User ID (TEXT) PRIMARY KEY
 *      Device ID (INTEGER)
 *      Auth Token (TEXT)
 *      Identity Keypair (BLOB)
 *      Pre Key Keypair (BLOB)
 * One Time
 *      Keypair (BLOB) PRIMARY KEY
 * Users
 *      User ID (TEXT) PRIMARY KEY
 *      stale (INTEGER)
 * Devices
 *      Device ID (INTEGER) PRIMARY KEY
 *      User ID (TEXT) FOREIGN KEY
 *      stale (INTEGER)
 * Sessions
 *      Session ID (INTEGER) PRIMARY KEY
 *      User ID (TEXT) FOREIGN KEY
 *      Device ID (INTEGER) FOREIGN KEY
 *      Contents (BLOB)
 *      Public Key (BLOB)
 *      stale (INTEGER)
 */
namespace client::db {
    class database {
    public:
        database(const char* db_name);
        ~database();
        database(const database&) = delete;
        database(database&&) = default;
        database& operator=(database&&) = default;
        database& operator=(const database&) = delete;

        void save_registration(const std::string& email, const int device_id,
                const std::string& auth_token, const crypto::DH_Keypair& identity_keypair,
                const crypto::DH_Keypair& pre_keypair);

        void insert_one_time(const crypto::DH_Keypair& one_time);
        void insert_user_record(const std::string& email);
        void insert_device_record(const std::string& email, const int device_id);
        void insert_session(const std::string& email, const int device_index, const session& s);

        void delete_user_record(const std::string& email);
        void delete_device_record(const std::string& email, const int device_index);
        void delete_session(const std::string& email, const int device_index, const session& s);

        void activate_session(const std::string& email, const int device_index, const session& s);

        void mark_user_stale(const std::string& email);
        void mark_device_stale(const std::string& email, const int device_index);

    private:
        sqlite3* db_conn;

        sqlite3_stmt* self_insert;
        sqlite3_stmt* users_insert;
        sqlite3_stmt* devices_insert;
        sqlite3_stmt* one_time_insert;
        sqlite3_stmt* sessions_insert;

        sqlite3_stmt* one_time_update;
        sqlite3_stmt* sessions_update;

        sqlite3_stmt* users_delete;
        sqlite3_stmt* devices_delete;
        sqlite3_stmt* one_time_delete;
        sqlite3_stmt* sessions_delete;

        void prepare_statement(const char* sql, sqlite3_stmt** stmt);
        void exec_statement(const char* sql);
        void throw_db_error();
    };

    constexpr auto IN_MEMORY_DB = ":memory:";

    constexpr auto create_self = "\
        CREATE TABLE IF NOT EXISTS self (\
           user_id      TEXT    PRIMARY KEY,\
           device_id    INTEGER NOT NULL,\
           auth_token   TEXT    NOT NULL,\
           identity     BLOB    NOT NULL,\
           pre_key      BLOB    NOT NULL,\
           CHECK(length(user_id) > 0 and length(auth_token) > 0 and device_id > 0)\
        );";
    constexpr auto create_one_time = "\
        CREATE TABLE IF NOT EXISTS one_time (\
           key_pair     BLOB PRIMARY KEY,\
           CHECK(length(key_pair) > 0)\
        );";
    constexpr auto create_users = "\
        CREATE TABLE IF NOT EXISTS users (\
           user_id      TEXT     PRIMARY KEY,\
           stale        INTEGER  NOT NULL,\
           CHECK(length(user_id) > 0 and stale >= 0 and stale <= 1)\
        );";
    constexpr auto create_devices = "\
        CREATE TABLE IF NOT EXISTS devices (\
           device_id    INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           stale        INTEGER  NOT NULL,\
           FOREIGN KEY(user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           CHECK(length(user_id) > 0 and stale >= 0 and stale <= 1)\
        );";
    constexpr auto create_sessions = "\
        CREATE TABLE IF NOT EXISTS devices (\
           session_id   INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           device_id    INTEGER NOT NULL,\
           contents     BLOB    NOT NULL UNIQUE,\
           public_key   BLOB    NOT NULL,\
           stale        INTEGER NOT NULL,\
           FOREIGN KEY(user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY(device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           CHECK(length(identity_key) > 0 and length(pre_key) > 0 and length(signature) > 0)\
        );";

    constexpr auto insert_device = "INSERT INTO devices(user_id, identity_key, pre_key, signature) \
                                    VALUES (?1, ?2, ?3, ?4);";

    constexpr auto update_pre_key_stmt
            = "UPDATE devices SET pre_key = ?1, signature = ?2 WHERE device_id = ?3;";

    constexpr auto delete_user = "DELETE FROM users WHERE user_id = ?1;";

    constexpr auto select_devices_user_id
            = "SELECT device_id, identity_key, pre_key, signature FROM devices WHERE user_id = ?1;";
} // namespace client::db

#endif /* end of include guard: SERVER_STATE_H */
