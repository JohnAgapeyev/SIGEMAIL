#include <cstring>
#include <sqlite3.h>

#include "db_utils.h"
#include "error.h"
#include "logging.h"

void prepare_statement(sqlite3* db_conn, const char* sql, sqlite3_stmt** stmt) {
    if (sqlite3_prepare_v2(db_conn, sql, strlen(sql) + 1, stmt, nullptr) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
}

void exec_statement(sqlite3* db_conn, const char* sql) {
    char* err_msg = nullptr;

    if (sqlite3_exec(db_conn, sql, nullptr, nullptr, &err_msg)) {
        spdlog::error(err_msg);
        throw db_error(err_msg);
    }
    sqlite3_free(err_msg);
}

void throw_db_error(sqlite3* db_conn) {
    const auto err_msg = sqlite3_errmsg(db_conn);
    spdlog::error(err_msg);
    throw db_error(err_msg);
}

std::string read_db_string(sqlite3* db_conn, sqlite3_stmt* stmt, const int column_index) {
    const auto data = sqlite3_column_text(stmt, column_index);
    if (!data) {
        throw_db_error(db_conn);
    }
    const int data_len = sqlite3_column_bytes(stmt, column_index);
    return std::string{reinterpret_cast<const char*>(data), static_cast<unsigned long>(data_len)};
}
