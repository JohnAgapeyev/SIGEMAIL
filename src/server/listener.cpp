#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <utility>

#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"

listener::listener(boost::asio::io_context& ioc, ssl::context& ssl_ctx, tcp::endpoint endpoint,
        server::db::database& db) :
        ctx(ssl_ctx),
        acceptor(ioc), socket(ioc), server_db(db) {
    boost::system::error_code ec;

    // Open the acceptor
    acceptor.open(endpoint.protocol(), ec);
    if (ec) {
        //Open failed
        spdlog::error("Open failed");
        return;
    }

    // Allow address reuse
    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
        spdlog::error("Unable to reuse address");
        return;
    }

    // Bind to the server address
    acceptor.bind(endpoint, ec);
    if (ec) {
        //Bind failed
        spdlog::error("Failed to bind");
        return;
    }

    // Start listening for connections
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        //Listen failed
        spdlog::error("Failed to listen");
        return;
    }
}

// Start accepting incoming connections
void listener::run() {
    if (!acceptor.is_open()) {
        spdlog::error("Tried to accept when acceptor isn't open");
        return;
    }
    do_accept();
}

void listener::do_accept() {
    acceptor.async_accept(
            socket, std::bind(&listener::on_accept, shared_from_this(), std::placeholders::_1));
}

void listener::on_accept(boost::system::error_code ec) {
    if (ec) {
        //Accept failed
        spdlog::trace("Accept failed");
    } else {
        // Create the http session and run it
        std::make_shared<http_session>(std::move(socket), ctx, server_db)->run();
    }
    // Accept another connection
    do_accept();
}
