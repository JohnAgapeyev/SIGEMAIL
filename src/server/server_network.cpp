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
    // Perform the SSL handshake
    ws.next_layer().async_handshake(ssl::stream_base::server,
            boost::asio::bind_executor(strand,
                    std::bind(&server_network_session::on_handshake, shared_from_this(),
                            std::placeholders::_1)));
}

void server_network_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
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
        return;
    }

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
        return;
    }

    if (ec) {
        //Read failed
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
        return;
    }

    // Allow address reuse
    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
        return;
    }

    // Bind to the server address
    acceptor.bind(endpoint, ec);
    if (ec) {
        //Bind failed
        return;
    }

    // Start listening for connections
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        //Listen failed
        return;
    }
}

// Start accepting incoming connections
void listener::run() {
    if (!acceptor.is_open()) {
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
    } else {
        // Create the server_network_session and run it
        std::make_shared<server_network_session>(std::move(socket), ctx)->run();
    }

    // create color multi threaded logger
    auto console = spdlog::stdout_color_mt("console");
    console->info("Welcome to spdlog!");
    console->error("Some error message with arg: {}", 1);

    auto err_logger = spdlog::stderr_color_mt("stderr");
    err_logger->error("Some error message");

    // Formatting examples
    console->warn("Easy padding in numbers like {:08d}", 12);
    console->critical("Support for int: {0:d};  hex: {0:x};  oct: {0:o}; bin: {0:b}", 42);
    console->info("Support for floats {:03.2f}", 1.23456);
    console->info("Positional args are {1} {0}..", "too", "supported");
    console->info("{:<30}", "left aligned");

    spdlog::get("console")->info("loggers can be retrieved from a global registry using the spdlog::get(logger_name)");

    // Runtime log levels
    spdlog::set_level(spdlog::level::info); // Set global log level to info
    console->debug("This message should not be displayed!");
    console->set_level(spdlog::level::trace); // Set specific logger's log level
    console->debug("This message should be displayed..");

    // Customize msg format for all loggers
    spdlog::set_pattern("[%H:%M:%S %z] [%n] [%^---%L---%$] [thread %t] %v");
    console->info("This an info message with custom format");

    // Compile time log levels
    // define SPDLOG_DEBUG_ON or SPDLOG_TRACE_ON
    SPDLOG_TRACE(console, "Enabled only #ifdef SPDLOG_TRACE_ON..{} ,{}", 1, 3.23);
    SPDLOG_DEBUG(console, "Enabled only #ifdef SPDLOG_DEBUG_ON.. {} ,{}", 1, 3.23);

    // Accept another connection
    do_accept();
}
