#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

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
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

// Echoes back all received HTTP requests
class http_session : public std::enable_shared_from_this<http_session> {
public:
    // Take ownership of the socket
    http_session(tcp::socket tcp_socket, ssl::context& ctx) :
            stream(std::move(tcp_socket), ctx), strand(stream.get_executor()) {}

    // Start the asynchronous operation
    void run();
    void on_handshake(boost::system::error_code ec);
    void do_read();
    void on_read(boost::system::error_code ec);
    void on_write(boost::system::error_code ec, bool close);
    void do_close();

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<class Body, class Allocator, class Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send);

private:
    ssl::stream<tcp::socket> stream;
    http::request<http::string_body> request;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::flat_buffer buffer;
    std::shared_ptr<void> result;
};

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