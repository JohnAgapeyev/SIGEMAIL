#ifndef TEST_H
#define TEST_H

#include <memory>
#include <vector>

#include "client_network.h"
#include "client_state.h"
#include "crypto.h"
#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"
#include "session.h"

struct Server_DB_Pair {
    Server_DB_Pair(tcp::endpoint endpoint, server::database& in_db);
    ~Server_DB_Pair();

    boost::asio::io_context ioc;
    boost::asio::ssl::context ssl;
    server::database& db;
    std::shared_ptr<listener> listen;
};

struct DisableLogging {
    DisableLogging();
    ~DisableLogging() = default;
};

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

std::array<std::byte, 24> get_truncated_hash(const std::string_view data);

session get_session();

server::database get_server_db();
client::database get_client_db();

std::shared_ptr<client_network_session> get_client(client::database& db);
std::shared_ptr<Server_DB_Pair> get_server(server::database& db);

#endif /* end of include guard: TEST_H */
