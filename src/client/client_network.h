#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

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

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket; // from <boost/beast/websocket.hpp>

// Sends a WebSocket message and prints the response
class client_network_session : public std::enable_shared_from_this<client_network_session> {
public:
    // Resolver and socket require an io_context
    explicit client_network_session(boost::asio::io_context& ioc, ssl::context& ctx) :
            resolver_(ioc), ws_(ioc, ctx) {}

    void run(char const* host, char const* port, char const* text);
    void on_resolve(boost::system::error_code ec, tcp::resolver::results_type results);
    void on_connect(boost::system::error_code ec);
    void on_ssl_handshake(boost::system::error_code ec);
    void on_handshake(boost::system::error_code ec);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_close(boost::system::error_code ec);

private:
    tcp::resolver resolver_;
    websocket::stream<ssl::stream<tcp::socket>> ws_;
    boost::beast::multi_buffer buffer_;
    std::string host_;
    std::string text_;
};

#endif /* end of include guard: CLIENT_NETWORK_H */
