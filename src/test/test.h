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
    Server_DB_Pair(ssl::context& ssl_ctx, tcp::endpoint endpoint) :
            ioc(), db(get_db()), listen(std::make_shared<listener>(ioc, ssl_ctx, endpoint, db)) {
        listen->run();
        std::thread{[this]() {
            spdlog::error("Pre ioc");
            ioc.run();
            spdlog::error("Post ioc");
        }}.detach();
    }
    ~Server_DB_Pair() {
        ioc.stop();
    }

    boost::asio::io_context ioc;
    db::database db;
    std::shared_ptr<listener> listen;
};

struct Client_Fixture {
    Client_Fixture(ssl::context& ctx, const char* dest_host, const char* dest_port) :
            cns(std::make_shared<client_network_session>(ioc, ctx, dest_host, dest_port)) {
        std::thread{[this]() { ioc.run(); }}.detach();
    }
    ~Client_Fixture() { ioc.stop(); }

    boost::asio::io_context ioc;
    std::shared_ptr<client_network_session> cns;
};

struct DisableLogging {
    DisableLogging() {
        auto logger = spdlog::create<spdlog::sinks::null_sink_st>("null_logger");
        //spdlog::set_default_logger(logger);
    }
    ~DisableLogging() = default;
};

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

std::array<std::byte, 24> get_truncated_hash(const std::string_view data);

session get_session();

std::shared_ptr<Client_Fixture> get_client();
std::shared_ptr<Server_DB_Pair> get_server();

#endif /* end of include guard: TEST_H */
