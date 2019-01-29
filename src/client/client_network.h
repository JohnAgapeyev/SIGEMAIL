#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

class client_network_session : public std::enable_shared_from_this<client_network_session> {
public:
    // Resolver requires an io_context
    client_network_session(boost::asio::io_context& ioc, ssl::context& ctx, const char *dest_host, const char *dest_port);
    ~client_network_session();

    void test_request();

private:
    tcp::resolver resolver;
    ssl::stream<tcp::socket> stream;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::flat_buffer buffer;
    http::request<http::string_body> req;
    http::response<http::string_body> res;
    std::string host;
    std::string text;
};

#endif /* end of include guard: CLIENT_NETWORK_H */
