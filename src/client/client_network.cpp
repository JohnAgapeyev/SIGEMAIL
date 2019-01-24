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

// Start the asynchronous operation
void client_network_session::run(
        const char* dest_host, const char* dest_port, const char* mesg_text) {
    // Save these for later
    host = dest_host;
    text = mesg_text;

    // Set up an HTTP GET request message
    req.method(http::verb::get);
    req.target("foobar");
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver.async_resolve(dest_host, dest_port,
            std::bind(&client_network_session::on_resolve, shared_from_this(),
                    std::placeholders::_1, std::placeholders::_2));
}

void client_network_session::on_resolve(
        boost::system::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        //Resolve failed
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
        return;
    }

    // Send the message
    http::async_write(stream, req,
            std::bind(&client_network_session::on_write, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_write(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Write failed
        return;
    }

    // Read a message into our buffer
    http::async_read(stream, buffer, res,
            std::bind(&client_network_session::on_read, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Read failed
        return;
    }

    // Gracefully close the stream
    stream.async_shutdown(std::bind(
            &client_network_session::on_shutdown, shared_from_this(), std::placeholders::_1));
}

void client_network_session::on_shutdown(boost::system::error_code ec) {
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }
    if (ec) {
        //Shutdown failed
        return;
        //return fail(ec, "shutdown");
    }

    // If we get here then the connection is closed gracefully
}
