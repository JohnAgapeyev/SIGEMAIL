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
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <string>
#include <thread>
#include <vector>

#include "server_network.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket; // from <boost/beast/websocket.hpp>

// Start the asynchronous operation
void websocket_session::run() {
    spdlog::get("console")->debug("Starting SSL Handshake");
    // Perform the SSL handshake
    ws.next_layer().async_handshake(ssl::stream_base::server,
            boost::asio::bind_executor(strand,
                    std::bind(&websocket_session::on_handshake, shared_from_this(),
                            std::placeholders::_1)));
}

void websocket_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        spdlog::get("console")->error("SSL Handshake failed");
        return;
    }

    // Accept the websocket handshake
    ws.async_accept(boost::asio::bind_executor(strand,
            std::bind(&websocket_session::on_accept, shared_from_this(), std::placeholders::_1)));
}

void websocket_session::on_accept(boost::system::error_code ec) {
    //Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted) {
        spdlog::get("console")->info("Websocket Accept aborted");
        return;
    }
    if (ec) {
        //Accept failed
        spdlog::get("console")->error("Websocket Accept failed");
        return;
    }
    spdlog::get("console")->info("Secure Websocket connection established");

    // Read a message
    do_read();
}

void websocket_session::do_read() {
    // Read a message into our buffer
    ws.async_read(buffer,
            boost::asio::bind_executor(strand,
                    std::bind(&websocket_session::on_read, shared_from_this(),
                            std::placeholders::_1, std::placeholders::_2)));
}

void websocket_session::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    // This indicates that the websocket_session was closed
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
                    std::bind(&websocket_session::on_write, shared_from_this(),
                            std::placeholders::_1, std::placeholders::_2)));
}

void websocket_session::on_write(boost::system::error_code ec, std::size_t bytes_transferred) {
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

void websocket_session::on_timer(boost::system::error_code ec) {
    if (ec && ec != boost::asio::error::operation_aborted) {
        spdlog::get("console")->error("Timer failure");
        return;
    }

    // See if the timer really expired since the deadline may have moved.
    if (timer.expiry() <= std::chrono::steady_clock::now()) {
        // If this is the first time the timer expired,
        // send a ping to see if the other end is there.
        if (ws.is_open() && ping_state == 0) {
            // Note that we are sending a ping
            ping_state = 1;

            // Set the timer
            timer.expires_after(std::chrono::seconds(15));

            // Now send the ping
            ws.async_ping({},
                    boost::asio::bind_executor(strand,
                            std::bind(&websocket_session::on_ping, shared_from_this(),
                                    std::placeholders::_1)));
        } else {
            // The timer expired while trying to handshake,
            // or we sent a ping and it never completed or
            // we never got back a control frame, so close.

            // Closing the socket cancels all outstanding operations. They
            // will complete with boost::asio::error::operation_aborted
            ws.next_layer().next_layer().shutdown(tcp::socket::shutdown_both, ec);
            ws.next_layer().next_layer().close(ec);
            return;
        }
    }

    // Wait on the timer
    timer.async_wait(boost::asio::bind_executor(strand,
            std::bind(&websocket_session::on_timer, shared_from_this(), std::placeholders::_1)));
}

void websocket_session::activity() { // Note that the connection is alive
    ping_state = 0;

    // Set the timer
    timer.expires_after(std::chrono::seconds(15));
}

void websocket_session::on_ping(boost::system::error_code ec) {
    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    if (ec) {
        spdlog::get("console")->error("Ping failed");
        return;
    }

    // Note that the ping was sent.
    if (ping_state == 1) {
        ping_state = 2;
    } else {
        // ping_state_ could have been set to 0
        // if an incoming control frame was received
        // at exactly the same time we sent a ping.
        if (ping_state != 0) {
            spdlog::get("console")->error("Open failed");
        }
    }
}

void websocket_session::on_control_callback(
        websocket::frame_type kind, boost::beast::string_view payload) {
    boost::ignore_unused(kind, payload);
    // Note that there is activity
    activity();
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
        std::make_shared<websocket_session>(std::move(socket), ctx)->run();
    }
    // Accept another connection
    do_accept();
}
