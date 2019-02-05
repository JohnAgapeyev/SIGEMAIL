#ifndef LISTENER_H
#define LISTENER_H

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <utility>

#include "server_state.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

// Accepts incoming connections and launches the websocket_sessions
class listener : public std::enable_shared_from_this<listener> {
public:
    listener(boost::asio::io_context& ioc, ssl::context& ssl_ctx, tcp::endpoint endpoint, server::db::database& db);
    ~listener() = default;

    // Start accepting incoming connections
    void run();
    void do_accept();
    void on_accept(boost::system::error_code ec);

private:
    ssl::context& ctx;
    tcp::acceptor acceptor;
    tcp::socket socket;

    server::db::database& server_db;
};

#endif /* end of include guard: LISTENER_H */
