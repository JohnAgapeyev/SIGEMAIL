#include <cstring>
#include <sqlite3.h>
#include <cstring>

#include "db_utils.h"
#include "error.h"
#include "logging.h"

sqlite3_stmt* prepare_statement(sqlite3* db_conn, const char* sql) {
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_conn, sql, strlen(sql) + 1, &stmt, nullptr) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
    return stmt;
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

db_statement::db_statement(sqlite3*& dbc, const char* sql) :
        db_conn(dbc), stmt(prepare_statement(db_conn, sql), sqlite3_finalize), mut() {}

void db_statement::bind_text(const int index, const std::string_view str) {
    std::lock_guard<std::mutex> lg{mut};
    if (sqlite3_bind_text(stmt.get(), index, str.data(), str.size(), SQLITE_TRANSIENT)
            != SQLITE_OK) {
        throw_db_error(db_conn);
    }
}
void db_statement::bind_blob(const int index, const std::byte* data, const std::size_t len) {
    std::lock_guard<std::mutex> lg{mut};
    if (sqlite3_bind_blob(stmt.get(), index, data, len, SQLITE_TRANSIENT) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
}

void db_statement::bind_int(const int index, const int num) {
    std::lock_guard<std::mutex> lg{mut};
    if (sqlite3_bind_int(stmt.get(), index, num) != SQLITE_OK) {
        throw_db_error(db_conn);
    }
}

bool db_statement::execute_row() {
    std::lock_guard<std::mutex> lg{mut};
    //Shouldn't need to clear bindings since I never reuse binding between calls
    sqlite3_reset(stmt.get());
retry:
    if (int err = sqlite3_step(stmt.get()); err != SQLITE_ROW) {
        if (err == SQLITE_BUSY) {
            std::this_thread::yield();
            goto retry;
        }
        if (err == SQLITE_DONE) {
            return false;
        }
        throw_db_error(db_conn);
    }
    return true;
}

void db_statement::execute_done() {
    std::lock_guard<std::mutex> lg{mut};
    run_stmt(SQLITE_DONE);
}

/*
 * successful_res should be either SQLITE_DONE or SQLITE_ROW
 */
void db_statement::run_stmt(const int successful_res) {
    //Shouldn't need to clear bindings since I never reuse binding between calls
    sqlite3_reset(stmt.get());
retry:
    if (int err = sqlite3_step(stmt.get()); err != successful_res) {
        if (err == SQLITE_BUSY) {
            std::this_thread::yield();
            goto retry;
        }
        throw_db_error(db_conn);
    }
}

int db_statement::column_int(const int index) {
    return sqlite3_column_int(stmt.get(), index);
}

std::string db_statement::column_text(const int index) {
    return read_db_string(db_conn, stmt.get(), index);
}

std::vector<std::byte> db_statement::column_blob(const int index) {
    const std::byte *data = static_cast<const std::byte *>(sqlite3_column_blob(stmt.get(), index));
    if (!data) {
        throw_db_error(db_conn);
    }
    const int data_len = sqlite3_column_bytes(stmt.get(), index);
    std::vector<std::byte> tmp_buf{data, data + data_len};
    return tmp_buf;
}
