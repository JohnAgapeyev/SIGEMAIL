#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "logging.h"
#include "server_network.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

void http_session::run() {
    // Make sure we run on the strand
    if (!strand.running_in_this_thread()) {
        return boost::asio::post(boost::asio::bind_executor(
                strand, std::bind(&http_session::run, shared_from_this())));
    }

    spdlog::get("console")->debug("Starting SSL Handshake");

    // Perform the SSL handshake
    stream.async_handshake(ssl::stream_base::server,
            boost::asio::bind_executor(strand,
                    std::bind(&http_session::on_handshake, shared_from_this(),
                            std::placeholders::_1)));
}

void http_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        spdlog::get("console")->error("SSL Handshake failed");
        return;
    }
    do_read();
}

void http_session::do_read() {
    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    request = {};

    // Read a request
    http::async_read(stream, buffer, request,
            boost::asio::bind_executor(strand,
                    std::bind(&http_session::on_read, shared_from_this(), std::placeholders::_1)));
}

void http_session::on_read(boost::system::error_code ec) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    // This means they closed the connection
    if (ec == http::error::end_of_stream) {
        do_close();
        return;
    }

    if (ec) {
        spdlog::get("console")->error("Read failed");
        return;
    }

    // Send the response
    handle_request(std::move(request), [this](auto&& msg) {
        // The lifetime of the message has to extend
        // for the duration of the async operation so
        // we use a shared_ptr to manage it.
        const auto sp = std::make_shared<std::remove_reference_t<decltype(msg)>>(std::move(msg));

        // Store a type-erased version of the shared
        // pointer in the class to keep it alive.
        result = sp;

        // Write the response
        http::async_write(stream, *sp,
                boost::asio::bind_executor(strand,
                        std::bind(&http_session::on_write, shared_from_this(),
                                std::placeholders::_1, sp->need_eof())));
    });
}

void http_session::on_write(boost::system::error_code ec, bool close) {
    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    if (ec) {
        spdlog::get("console")->error("Write failed");
        return;
    }

    if (close) {
        // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
        do_close();
        return;
    }

    // Read another request
    do_read();
}

void http_session::do_close() {
    // Send a SSL+TCP shutdown
    stream.shutdown();
    stream.lowest_layer().shutdown(tcp::socket::shutdown_both);
    stream.lowest_layer().close();

    // At this point the connection is closed gracefully
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
        // Create the websocket_session and run it
        std::make_shared<http_session>(std::move(socket), ctx)->run();
    }
    // Accept another connection
    do_accept();
}
