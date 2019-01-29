#ifndef TEST_H
#define TEST_H

#include <memory>
#include <vector>

#include "client_network.h"
#include "crypto.h"
#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"
#include "session.h"

db::database get_db();

struct Server_DB_Pair {
    Server_DB_Pair(boost::asio::io_context& ioc, ssl::context& ssl_ctx, tcp::endpoint endpoint) :
            io_c(ioc), listen(ioc, ssl_ctx, endpoint, db) {}
    ~Server_DB_Pair() { io_c.stop(); }

    boost::asio::io_context& io_c;
    db::database db{get_db()};
    listener listen;
};

struct DisableLogging {
    DisableLogging() {
        auto logger = spdlog::create<spdlog::sinks::null_sink_st>("null_logger");
        spdlog::set_default_logger(logger);
    }
    ~DisableLogging() = default;
};

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

std::array<std::byte, 24> get_truncated_hash(const std::string_view data);

session get_session();

std::shared_ptr<client_network_session> get_client();
std::shared_ptr<Server_DB_Pair> get_server();

#endif /* end of include guard: TEST_H */
