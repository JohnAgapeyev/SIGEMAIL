#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "client_network.h"
#include "logging.h"

//This currently has some sort of error going on for stream shutdown, need to diagnose and handle
client_network_session::~client_network_session() {
#if 0
    boost::system::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    } else {
        spdlog::debug("Client shutdown error: {}", ec.message());
    }
    stream.lowest_layer().shutdown(boost::asio::socket_base::shutdown_both);
    stream.lowest_layer().close();
#endif
}

// Start the asynchronous operation
void client_network_session::run(const char* dest_host, const char* dest_port) {
    // Save these for later
    host = dest_host;

    // Set up an HTTP GET request message
    req.method(http::verb::get);
    req.target("/v1/accounts/email/code/foobar@test.com");
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver.async_resolve(dest_host, dest_port,
            std::bind(&client_network_session::on_resolve, shared_from_this(),
                    std::placeholders::_1, std::placeholders::_2));
}

void client_network_session::test_request() {
    req.method(http::verb::get);
    req.target("/v1/keys/foobar@test.com/123456");
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    http::async_write(stream, req,
            std::bind(&client_network_session::on_write, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_resolve(
        boost::system::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        //Resolve failed
        spdlog::error("Resolve failed: {}", ec.message());
        return;
    }

    // Make the connection on the IP address we get from a lookup
    boost::asio::async_connect(stream.next_layer(), results.begin(), results.end(),
            std::bind(&client_network_session::on_connect, shared_from_this(),
                    std::placeholders::_1));
}

void client_network_session::on_connect(boost::system::error_code ec) {
    if (ec) {
        //Connect failed
        spdlog::error("Connect failed: {}", ec.message());
        return;
    }

    // Perform the SSL handshake
    stream.async_handshake(ssl::stream_base::client,
            std::bind(&client_network_session::on_handshake, shared_from_this(),
                    std::placeholders::_1));
}

void client_network_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        spdlog::error("SSL Handshake failed: {}", ec.message());
        return;
    }

    stream.lowest_layer().set_option(boost::asio::socket_base::keep_alive{true});

    // Send the message
    http::async_write(stream, req,
            std::bind(&client_network_session::on_write, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_write(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Write failed
        spdlog::error("Write failed: {}", ec.message());
        return;
    }

    spdlog::debug("Request sent");

    // Read a message into our buffer
    http::async_read(stream, buffer, res,
            std::bind(&client_network_session::on_read, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Read failed
        spdlog::error("Read failed: {}", ec.message());
        return;
    }

#if 0
    // Gracefully close the stream
    stream.async_shutdown(std::bind(
            &client_network_session::on_shutdown, shared_from_this(), std::placeholders::_1));
#endif
}

void client_network_session::on_shutdown(boost::system::error_code ec) {
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }
    if (ec) {
        //Shutdown failed
        spdlog::error("Shutdown failed: {}", ec.message());
        return;
        //return fail(ec, "shutdown");
    }

    // If we get here then the connection is closed gracefully
}
