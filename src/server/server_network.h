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
            stream(std::move(tcp_socket), ctx), strand(stream.get_executor()),
            timer(stream.get_executor().context(), (std::chrono::steady_clock::time_point::max)()) {
    }

    // Start the asynchronous operation
    void run();
    void on_handshake(boost::system::error_code ec);
    void do_read();
    void on_read(boost::system::error_code ec);
    void on_write(boost::system::error_code ec, bool close);
    void on_timer(boost::system::error_code ec);
    void do_close();

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<class Body, class Allocator, class Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) {
        // Returns a bad request response
        const auto bad_request = [&req](boost::beast::string_view why) {
            http::response<http::string_body> res{http::status::bad_request, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = why.to_string();
            res.prepare_payload();
            return res;
        };

        // Returns a not found response
        const auto not_found = [&req](boost::beast::string_view target) {
            http::response<http::string_body> res{http::status::not_found, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "The resource '" + target.to_string() + "' was not found.";
            res.prepare_payload();
            return res;
        };

        // Returns a server error response
        const auto server_error = [&req](boost::beast::string_view what) {
            http::response<http::string_body> res{
                    http::status::internal_server_error, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "An error occurred: '" + what.to_string() + "'";
            res.prepare_payload();
            return res;
        };

        // Make sure we can handle the method
        if (req.method() != http::verb::get && req.method() != http::verb::head)
            return send(bad_request("Unknown HTTP-method"));

        // Request path must be absolute and not contain "..".
        if (req.target().empty() || req.target()[0] != '/'
                || req.target().find("..") != boost::beast::string_view::npos)
            return send(bad_request("Illegal request-target"));

        // Build the path to the requested file
        std::string path = req.target().to_string();
        if (req.target().back() == '/')
            path.append("index.html");

        // Attempt to open the file
        boost::beast::error_code ec;
        http::file_body::value_type body;
        body.open(path.c_str(), boost::beast::file_mode::scan, ec);

        // Handle the case where the file doesn't exist
        if (ec == boost::system::errc::no_such_file_or_directory)
            return send(not_found(req.target()));

        // Handle an unknown error
        if (ec)
            return send(server_error(ec.message()));

        // Cache the size since we need it after the move
        auto const size = body.size();

        // Respond to HEAD request
        if (req.method() == http::verb::head) {
            http::response<http::empty_body> res{http::status::ok, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.content_length(size);
            res.keep_alive(req.keep_alive());
            return send(std::move(res));
        }

        // Respond to GET request
        http::response<http::file_body> res{std::piecewise_construct,
                std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.content_length(size);
        res.keep_alive(req.keep_alive());

        return send(std::move(res));

        http::async_write(stream, res,
                boost::asio::bind_executor(strand,
                        std::bind(&http_session::on_write, shared_from_this(),
                                std::placeholders::_1, res.need_eof())));
    }

private:
    ssl::stream<tcp::socket> stream;
    http::request<http::string_body> request;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::asio::steady_timer timer;
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
