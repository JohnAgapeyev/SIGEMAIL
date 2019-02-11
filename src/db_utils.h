#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <sqlite3.h>
#include <string>

static constexpr auto IN_MEMORY_DB = ":memory:";

void prepare_statement(sqlite3* db_conn, const char* sql, sqlite3_stmt** stmt);
void exec_statement(sqlite3* db_conn, const char* sql);
void throw_db_error(sqlite3* db_conn);
std::string read_db_string(sqlite3* db_conn, sqlite3_stmt *stmt, const int column_index);

#endif
