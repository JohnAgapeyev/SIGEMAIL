#ifndef TEST_H
#define TEST_H

#include <vector>

#include "crypto.h"
#include "logging.h"
#include "server_state.h"
#include "session.h"

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

session get_session();

db::database get_db();

struct DisableLogging {
    DisableLogging() {
        auto logger = spdlog::create<spdlog::sinks::null_sink_st>("null_logger");
        spdlog::set_default_logger(logger);
    }
    ~DisableLogging() = default;
};

#endif /* end of include guard: TEST_H */
