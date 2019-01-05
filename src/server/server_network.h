#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket; // from <boost/beast/websocket.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

// Echoes back all received WebSocket messages
class websocket_session : public std::enable_shared_from_this<websocket_session> {
public:
    websocket_session(tcp::socket tcp_socket, ssl::context& ctx) :
#if 0
            socket(std::move(tcp_socket)),
#else
            ws(std::move(tcp_socket), ctx),
#endif
            strand(ws.get_executor()),
            timer(ws.get_executor().context(), (std::chrono::steady_clock::time_point::max)()) {
    }

    void run();
    void on_handshake(boost::system::error_code ec);

    template<typename Body, typename Allocator>
    void do_accept(http::request<Body, http::basic_fields<Allocator>> req) {
        // Set the control callback. This will be called
        // on every incoming ping, pong, and close frame.
        ws.control_callback(std::bind(&websocket_session::on_control_callback, this,
                std::placeholders::_1, std::placeholders::_2));

        // Run the timer. The timer is operated
        // continuously, this simplifies the code.
        on_timer({});

        // Set the timer
        timer.expires_after(std::chrono::seconds(15));

        // Accept the websocket handshake
        ws.async_accept(req,
                boost::asio::bind_executor(strand,
                        std::bind(&websocket_session::on_accept, shared_from_this(),
                                std::placeholders::_1)));
    }

    void on_accept(boost::system::error_code ec);
    void do_read();
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_timer(boost::system::error_code ec);
    void activity();
    void on_ping(boost::system::error_code ec);
    void on_control_callback(websocket::frame_type kind, boost::beast::string_view payload);

private:
#if 0
    tcp::socket socket;
#else
    websocket::stream<ssl::stream<tcp::socket>> ws;
#endif
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::multi_buffer buffer;
    boost::asio::steady_timer timer;
    uint8_t ping_state = 0;
};

#if 0
// Echoes back all received HTTP requests
class http_session : public std::enable_shared_from_this<http_session> {
public:
    // Take ownership of the socket
    http_session(tcp::socket tcp_socket, ssl::context& ctx) :
            socket(std::move(tcp_socket)), stream(socket, ctx), strand(stream.get_executor()) {}

    // Start the asynchronous operation
    void run();
    void on_handshake(boost::system::error_code ec);
    void on_accept(boost::system::error_code ec);
    void do_read();
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

private:
    tcp::socket socket;
    //boost::asio::steady_timer timer;
    ssl::stream<tcp::socket&> stream;
    http::request<http::string_body> req;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::flat_buffer buffer;
};
#endif

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the websocket_sessions
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
