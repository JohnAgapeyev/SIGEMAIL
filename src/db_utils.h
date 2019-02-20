#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <memory>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <vector>

static constexpr auto IN_MEMORY_DB = ":memory:";

sqlite3_stmt* prepare_statement(sqlite3* db_conn, const char* sql);
void exec_statement(sqlite3* db_conn, const char* sql);
void throw_db_error(sqlite3* db_conn);
std::string read_db_string(sqlite3* db_conn, sqlite3_stmt* stmt, const int column_index);

class db_statement {
public:
    db_statement(sqlite3*& dbc, const char* sql);
    db_statement(const db_statement&) = delete;
    db_statement(db_statement&&) = default;
    db_statement& operator=(const db_statement&) = delete;
    db_statement& operator=(db_statement&&) = default;

    void bind_text(const int index, const std::string_view str);
    void bind_blob(const int index, const std::byte* data, const std::size_t len);
    void bind_int(const int index, const int num);

    bool execute_row();
    void execute_done();

    int column_int(const int index);
    std::string column_text(const int index);
    std::vector<std::byte> column_blob(const int index);

private:
    sqlite3* db_conn;
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt;
    std::mutex mut;

    void run_stmt(const int successful_res);
};

#endif
