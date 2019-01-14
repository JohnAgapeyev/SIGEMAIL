#include <stdexcept>
#include <sqlite3.h>

#include "server_state.h"

db::database::database() {
    if (sqlite3_open("", &db_conn) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db_conn));
    }
}

db::database::~database() {
    sqlite3_close(db_conn);
}
