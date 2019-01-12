#ifndef SERVER_NETWORK_H
#define SERVER_NETWORK_H

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <string>
#include <utility>

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
    template<typename Body, typename Allocator, typename Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send);

private:
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            request_verification_code(const std::string_view email) const;
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            verify_verification_code(const std::string_view code) const;
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            register_prekeys() const;
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            lookup_prekey(const std::string_view user, const std::string_view device) const;
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            contact_intersection() const;
    template<typename Allocator>
    const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
            submit_message() const;

    ssl::stream<tcp::socket> stream;
    http::request<http::string_body> request;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    boost::beast::flat_buffer buffer;
    std::shared_ptr<void> result;
};

//------------------------------------------------------------------------------

#endif /* end of include guard: SERVER_NETWORK_H */
