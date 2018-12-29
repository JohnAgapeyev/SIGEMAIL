#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

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

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket; // from <boost/beast/websocket.hpp>

// Echoes back all received WebSocket messages
class server_network_session : public std::enable_shared_from_this<server_network_session> {
public:
    // Take ownership of the socket
    server_network_session(tcp::socket tcp_socket, ssl::context& ctx) :
            socket(std::move(tcp_socket)), ws(socket, ctx), strand(ws.get_executor()) {}

    // Start the asynchronous operation
    void run();
    void on_handshake(boost::system::error_code ec);
    void on_accept(boost::system::error_code ec);
    void do_read();
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

private:
    tcp::socket socket;
    websocket::stream<ssl::stream<tcp::socket&>> ws;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::multi_buffer buffer;
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the server_network_sessions
class listener : public std::enable_shared_from_this<listener> {
public:
    listener(boost::asio::io_context& ioc, ssl::context& ssl_ctx, tcp::endpoint endpoint);

    // Start accepting incoming connections
    void run();
    void do_accept();
    void on_accept(boost::system::error_code ec);

private:
    ssl::context& ctx;
    tcp::acceptor acceptor;
    tcp::socket socket;
};

#endif /* end of include guard: SERVER_NETWORK_H */
