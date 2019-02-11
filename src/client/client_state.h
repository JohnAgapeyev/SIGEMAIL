#ifndef CLIENT_STATE_H
#define CLIENT_STATE_H

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
 *      active_session (INTEGER) FOREIGN KEY
 *      stale (INTEGER)
 * Sessions
 *      Session ID (INTEGER) PRIMARY KEY
 *      User ID (TEXT) FOREIGN KEY
 *      Device ID (INTEGER) FOREIGN KEY
 *      Contents (BLOB)
 *      stale (INTEGER)
 */
namespace client {
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

        void add_one_time(const crypto::DH_Keypair& one_time);
        void add_user_record(const std::string& email);
        void add_device_record(const std::string& email, const int device_record);
        void add_session(const std::string& email, const int device_index, const session& s);

        void remove_user_record(const std::string& email);
        void remove_device_record(const int device_index);
        void remove_session(const int session_id);
        void remove_one_time(const crypto::public_key& public_key);

        void activate_session(const int device_index, const int session_id);

        void mark_user_stale(const std::string& email);
        void mark_device_stale(const int device_index);

        void purge_stale_records();

        std::tuple<std::string, int, std::string, crypto::DH_Keypair, crypto::DH_Keypair>
                get_self_data();
        crypto::DH_Keypair get_one_time_key(const crypto::public_key& public_key);

        std::vector<int> get_device_ids(const std::string& email);

        std::vector<std::pair<int, session>> get_sessions_by_device(const int device_id);

        session get_active_session(const int device_id);

    private:
        sqlite3* db_conn;

        sqlite3_stmt* self_insert;
        sqlite3_stmt* users_insert;
        sqlite3_stmt* devices_insert;
        sqlite3_stmt* one_time_insert;
        sqlite3_stmt* sessions_insert;

        sqlite3_stmt* users_update;
        sqlite3_stmt* devices_update;
        sqlite3_stmt* devices_update_active;
        sqlite3_stmt* one_time_update;
        sqlite3_stmt* sessions_update;

        sqlite3_stmt* users_delete;
        sqlite3_stmt* devices_delete;
        sqlite3_stmt* one_time_delete;
        sqlite3_stmt* sessions_delete;

        sqlite3_stmt* self_select;
        sqlite3_stmt* one_time_select;
        sqlite3_stmt* devices_select;
        sqlite3_stmt* sessions_select;
        sqlite3_stmt* active_select;

        static constexpr auto create_self = "\
        CREATE TABLE IF NOT EXISTS self (\
           user_id      TEXT    PRIMARY KEY,\
           device_id    INTEGER NOT NULL,\
           auth_token   TEXT    NOT NULL,\
           identity     BLOB    NOT NULL,\
           pre_key      BLOB    NOT NULL,\
           CHECK(length(user_id) > 0 and length(auth_token) > 0 and device_id > 0)\
        );";
        static constexpr auto create_one_time = "\
        CREATE TABLE IF NOT EXISTS one_time (\
           public_key     BLOB PRIMARY KEY,\
           contents       BLOB NOT NULL UNIQUE,\
           CHECK(length(contents) > 0 and length(public_key) > 0)\
        );";
        static constexpr auto create_users = "\
        CREATE TABLE IF NOT EXISTS users (\
           user_id      TEXT     PRIMARY KEY,\
           stale        INTEGER  NOT NULL,\
           CHECK(length(user_id) > 0 and stale >= 0 and stale <= 1)\
        );";
        static constexpr auto create_devices = "\
        CREATE TABLE IF NOT EXISTS devices (\
           device_id      INTEGER PRIMARY KEY,\
           user_id        TEXT    NOT NULL,\
           active_session INTEGER,\
           stale          INTEGER NOT NULL,\
           FOREIGN KEY(user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY(active_session) REFERENCES sessions(session_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           CHECK(length(user_id) > 0 and stale >= 0 and stale <= 1)\
        );";
        static constexpr auto create_sessions = "\
        CREATE TABLE IF NOT EXISTS sessions (\
           session_id   INTEGER PRIMARY KEY,\
           user_id      TEXT    NOT NULL,\
           device_id    INTEGER NOT NULL,\
           contents     BLOB    NOT NULL UNIQUE,\
           FOREIGN KEY(user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           FOREIGN KEY(device_id) REFERENCES devices(device_id) ON UPDATE CASCADE ON DELETE CASCADE,\
           CHECK(length(user_id) > 0 and length(contents) > 0)\
        );";

        static constexpr auto insert_self = "INSERT INTO self VALUES (?1, ?2, ?3, ?4, ?5);";
        static constexpr auto insert_one_time = "INSERT INTO one_time VALUES (?1, ?2);";
        static constexpr auto insert_users = "INSERT INTO users VALUES (?1, 0);";
        static constexpr auto insert_devices
                = "INSERT INTO devices(device_id, user_id, active_session, stale) VALUES (?2, ?1, NULL, 0);";
        static constexpr auto insert_sessions
                = "INSERT INTO sessions(user_id, device_id, contents) VALUES (?1, ?2, ?3);";

        static constexpr auto update_users = "UPDATE users SET stale = 1 WHERE user_id = ?1;";
        static constexpr auto update_devices = "UPDATE devices SET stale = 1 WHERE device_id = ?1;";
        static constexpr auto update_devices_active
                = "UPDATE devices SET active_session = ?2 WHERE device_id = ?1;";

        static constexpr auto delete_users = "DELETE FROM users WHERE user_id = ?1;";
        static constexpr auto delete_users_stale = "DELETE FROM users WHERE stale = 1;";
        static constexpr auto delete_devices = "DELETE FROM devices WHERE device_id = ?1;";
        static constexpr auto delete_devices_stale = "DELETE FROM devices WHERE stale = 1;";
        static constexpr auto delete_one_time = "DELETE FROM one_time WHERE public_key = ?1;";
        static constexpr auto delete_sessions = "DELETE FROM sessions WHERE session_id = ?1;";

        static constexpr auto select_self = "SELECT * FROM self LIMIT 1;";
        static constexpr auto select_one_time
                = "SELECT contents FROM one_time WHERE public_key = ?1;";
        static constexpr auto select_device_ids
                = "SELECT device_id FROM devices WHERE user_id = ?1;";
        static constexpr auto select_sessions
                = "SELECT session_id, contents FROM sessions WHERE device_id = ?1;";

        static constexpr auto select_active
                = "SELECT contents FROM sessions INNER JOIN devices ON devices.active_session = "
                  "sessions.session_id WHERE devices.device_id = ?1;";
    };
} // namespace client

#endif /* end of include guard: CLIENT_STATE_H */
