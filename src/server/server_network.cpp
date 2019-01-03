#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "server_network.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket; // from <boost/beast/websocket.hpp>

// Start the asynchronous operation
void server_network_session::run() {
    spdlog::get("console")->debug("Starting SSL Handshake");
    // Perform the SSL handshake
    ws.next_layer().async_handshake(ssl::stream_base::server,
            boost::asio::bind_executor(strand,
                    std::bind(&server_network_session::on_handshake, shared_from_this(),
                            std::placeholders::_1)));
}

void server_network_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        spdlog::get("console")->error("SSL Handshake failed");
        return;
    }

    // Accept the websocket handshake
    ws.async_accept(boost::asio::bind_executor(strand,
            std::bind(&server_network_session::on_accept, shared_from_this(),
                    std::placeholders::_1)));
}

void server_network_session::on_accept(boost::system::error_code ec) {
    if (ec) {
        //Accept failed
        spdlog::get("console")->error("Websocket Accept failed");
        return;
    }
    spdlog::get("console")->info("Secure Websocket connection established");

    // Read a message
    do_read();
}

void server_network_session::do_read() {
    // Read a message into our buffer
    ws.async_read(buffer,
            boost::asio::bind_executor(strand,
                    std::bind(&server_network_session::on_read, shared_from_this(),
                            std::placeholders::_1, std::placeholders::_2)));
}

void server_network_session::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    // This indicates that the server_network_session was closed
    if (ec == websocket::error::closed) {
        spdlog::get("console")->info("Session was closed");
        return;
    }

    if (ec) {
        //Read failed
        spdlog::get("console")->error("Read failed");
    }

    // Echo the message
    ws.text(ws.got_text());
    ws.async_write(buffer.data(),
            boost::asio::bind_executor(strand,
                    std::bind(&server_network_session::on_write, shared_from_this(),
                            std::placeholders::_1, std::placeholders::_2)));
}

void server_network_session::on_write(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Write failed
        spdlog::get("console")->error("Write failed");
        return;
    }

    // Clear the buffer
    buffer.consume(buffer.size());

    // Do another read
    do_read();
}

listener::listener(boost::asio::io_context& ioc, ssl::context& ssl_ctx, tcp::endpoint endpoint) :
        ctx(ssl_ctx), acceptor(ioc), socket(ioc) {
    boost::system::error_code ec;

    // Open the acceptor
    acceptor.open(endpoint.protocol(), ec);
    if (ec) {
        //Open failed
        spdlog::get("console")->error("Open failed");
        return;
    }

    // Allow address reuse
    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
        spdlog::get("console")->error("Unable to reuse address");
        return;
    }

    // Bind to the server address
    acceptor.bind(endpoint, ec);
    if (ec) {
        //Bind failed
        spdlog::get("console")->error("Failed to bind");
        return;
    }

    // Start listening for connections
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        //Listen failed
        spdlog::get("console")->error("Failed to listen");
        return;
    }
}

// Start accepting incoming connections
void listener::run() {
    if (!acceptor.is_open()) {
        spdlog::get("console")->error("Tried to accept when acceptor isn't open");
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
        spdlog::get("console")->trace("Accept failed");
    } else {
        // Create the server_network_session and run it
        std::make_shared<server_network_session>(std::move(socket), ctx)->run();
    }
    // Accept another connection
    do_accept();
}
