#include <boost/asio/signal_set.hpp>
#include <memory>
#include <thread>

#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"
#include "test.h"

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
    crypto::DH_Keypair kp;
    session s{key, kp.get_public()};
    return s;
}

db::database get_db() {
    return db::database{db::IN_MEMORY_DB};
}

std::array<std::byte, 24> get_truncated_hash(const std::string_view data) {
    const auto hash = crypto::hash_string(data);
    std::array<std::byte, 24> out;
    std::copy(hash.begin(), hash.begin() + 24, out.begin());
    return out;
}

std::shared_ptr<client_network_session> get_client() {
    boost::asio::io_context ioc;
    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tls};
    ctx.set_default_verify_paths();

    ctx.set_verify_mode(ssl::verify_none);

    std::shared_ptr<client_network_session> host_ref;
    try {
        host_ref = std::make_shared<client_network_session>(ioc, ctx, "localhost", "8443");
    } catch (const boost::system::system_error& e) {
        spdlog::error("Client network session failed to establish: {}", e.what());
        throw;
    }

    return host_ref;
}

std::shared_ptr<Server_DB_Pair> get_server(db::database& db) {
    return std::make_shared<Server_DB_Pair>(tcp::endpoint{tcp::v4(), 8443}, db);
}
