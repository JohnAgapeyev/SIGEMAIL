#include <sqlite3.h>
#include <stdexcept>

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
}

db::database::~database() {
    sqlite3_close(db_conn);
}
