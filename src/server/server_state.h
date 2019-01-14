#ifndef SERVER_STATE_H
#define SERVER_STATE_H

#include <sqlite3.h>

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
namespace db {
    class database {
    public:
        database();
        ~database();
        database(const database&) = delete;
        database(database&&) = default;
        database& operator=(database&&) = default;
        database& operator=(const database&) = delete;

    private:
        sqlite3* db_conn;
    };

    constexpr auto create_table = "\
        CREATE TABLE [IF NOT EXISTS] table_name (\
           column_1 data_type PRIMARY KEY,\
           column_2 data_type NOT NULL,\
           column_3 data_type DEFAULT 0,\
        table_constraint) [WITHOUT ROWID];";
} // namespace db

#endif /* end of include guard: SERVER_STATE_H */
