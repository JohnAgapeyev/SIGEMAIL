#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <sqlite3.h>

static constexpr auto IN_MEMORY_DB = ":memory:";

void prepare_statement(sqlite3* db_conn, const char* sql, sqlite3_stmt** stmt);
void exec_statement(sqlite3* db_conn, const char* sql);
void throw_db_error(sqlite3* db_conn);

#endif
