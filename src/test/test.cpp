#include <memory>
#include <thread>

#include "client_state.h"
#include "db_utils.h"
#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"
#include "test.h"

DisableLogging::DisableLogging() {
    auto logger = spdlog::create<spdlog::sinks::null_sink_st>("null_logger");
#if 0
    spdlog::set_level(spdlog::level::debug);
#else
    spdlog::set_default_logger(logger);
#endif
}

Server_DB_Pair::Server_DB_Pair(tcp::endpoint endpoint, server::database& in_db) :
        ioc(), ssl(boost::asio::ssl::context::tls), db(in_db) {
    load_server_certificate(ssl);
    listen = std::make_shared<listener>(ioc, ssl, endpoint, db);
    listen->run();
    t = std::thread{[this]() { ioc.run(); }};
}

Server_DB_Pair::~Server_DB_Pair() {
    ioc.stop();
    t.join();
}

Client_Wrapper::Client_Wrapper(
        const char* dest_host, const char* dest_port, client::database& in_db) :
        ioc(),
        ssl(boost::asio::ssl::context::tls) {
    ssl.set_default_verify_paths();
    ssl.set_verify_mode(ssl::verify_none);
    client = std::make_shared<client_network_session>(ioc, ssl, dest_host, dest_port, in_db);
}

crypto::secure_vector<std::byte> get_message() {
    crypto::secure_vector<std::byte> out;
    out.assign(76, std::byte{'a'});
    return out;
}

crypto::secure_vector<std::byte> get_aad() {
    crypto::secure_vector<std::byte> out;
    out.assign(3, std::byte{'b'});
    return out;
}

crypto::shared_key get_key() {
    crypto::shared_key out;
    out.fill(std::byte{'c'});
    return out;
}

session get_session() {
    const auto key = get_key();
    crypto::DH_Keypair kp1;
    crypto::DH_Keypair kp2;
    crypto::DH_Keypair kp3;
    crypto::DH_Keypair kp4;
    session s{key, kp3, kp1.get_public(), kp2.get_public(), kp4.get_public(),
            std::vector<std::byte>{13, std::byte{0xb4}}};
    return s;
}

server::database get_server_db() {
    return server::database{IN_MEMORY_DB};
}

client::database get_client_db() {
    return client::database{IN_MEMORY_DB};
}

std::array<std::byte, 24> get_truncated_hash(const std::string_view data) {
    const auto hash = crypto::hash_string(data);
    std::array<std::byte, 24> out;
    std::copy(hash.begin(), hash.begin() + 24, out.begin());
    return out;
}

std::shared_ptr<Client_Wrapper> get_client(client::database& db) {
    return std::make_shared<Client_Wrapper>("localhost", "8443", db);
}

std::shared_ptr<Server_DB_Pair> get_server(server::database& db) {
    return std::make_shared<Server_DB_Pair>(tcp::endpoint{tcp::v4(), 8443}, db);
}
