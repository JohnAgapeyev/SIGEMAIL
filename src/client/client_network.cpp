#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "client_network.h"

// Start the asynchronous operation
void client_network_session::run(const char* dest_host, const char* dest_port, const char* mesg_text) {
    // Save these for later
    host = dest_host;
    text = mesg_text;

    // Look up the domain name
    resolver.async_resolve(dest_host, dest_port,
            std::bind(&client_network_session::on_resolve, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_resolve(boost::system::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        //Resolve failed
        return;
    }

    // Make the connection on the IP address we get from a lookup
    boost::asio::async_connect(ws.next_layer().next_layer(), results.begin(), results.end(),
            std::bind(&client_network_session::on_connect, shared_from_this(), std::placeholders::_1));
}

void client_network_session::on_connect(boost::system::error_code ec) {
    if (ec) {
        //Connect failed
        return;
    }

    // Perform the SSL handshake
    ws.next_layer().async_handshake(ssl::stream_base::client,
            std::bind(&client_network_session::on_ssl_handshake, shared_from_this(), std::placeholders::_1));
}

void client_network_session::on_ssl_handshake(boost::system::error_code ec) {
    if (ec) {
        //SSL Handshake failed
        return;
    }

    // Perform the websocket handshake
    ws.async_handshake(host, "/",
            std::bind(&client_network_session::on_handshake, shared_from_this(), std::placeholders::_1));
}

void client_network_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        return;
    }

    // Send the message
    ws.async_write(boost::asio::buffer(text),
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
    ws.async_read(buffer,
            std::bind(&client_network_session::on_read, shared_from_this(), std::placeholders::_1,
                    std::placeholders::_2));
}

void client_network_session::on_read(boost::system::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        //Read failed
        return;
    }

    // Close the WebSocket connection
    ws.async_close(websocket::close_code::normal,
            std::bind(&client_network_session::on_close, shared_from_this(), std::placeholders::_1));
}

void client_network_session::on_close(boost::system::error_code ec) {
    if (ec) {
        //Close failed
        return;
    }

    // If we get here then the connection is closed gracefully

    // The buffers() function helps print a ConstBufferSequence
    std::cout << boost::beast::buffers(buffer.data()) << std::endl;
}
