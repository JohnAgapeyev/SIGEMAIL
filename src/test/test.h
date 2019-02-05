#ifndef TEST_H
#define TEST_H

#include <boost/asio/signal_set.hpp>
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
    Server_DB_Pair(tcp::endpoint endpoint, db::database& in_db) :
            ioc(), ssl(boost::asio::ssl::context::tls), db(in_db) {
        load_server_certificate(ssl);
        listen = std::make_shared<listener>(ioc, ssl, endpoint, db);
        listen->run();
        std::thread{[this]() { ioc.run(); }}.detach();
    }
    ~Server_DB_Pair() { ioc.stop(); }

    boost::asio::io_context ioc;
    boost::asio::ssl::context ssl;
    db::database& db;
    std::shared_ptr<listener> listen;
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
std::shared_ptr<Server_DB_Pair> get_server(db::database& db);

#endif /* end of include guard: TEST_H */
