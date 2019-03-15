#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include "client_state.h"
#include "message.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

class client_network_session : public std::enable_shared_from_this<client_network_session> {
public:
    // Resolver requires an io_context
    client_network_session(boost::asio::io_context& ioc, ssl::context& ctx, const char* dest_host,
            const char* dest_port, client::database& db);
    ~client_network_session();

    [[nodiscard]] bool request_verification_code(const std::string& email, const std::string& password);
    [[nodiscard]] bool verify_verification_code(const std::string& email, const std::string& password, const int code);
    [[nodiscard]] bool register_prekeys(const int key_count);
    [[nodiscard]] std::optional<std::vector<std::tuple<int, crypto::public_key, crypto::public_key,
            std::optional<crypto::public_key>>>>
            lookup_prekey(const std::string& user_id, const int device_id);
    [[nodiscard]] std::optional<std::vector<std::string>> contact_intersection(
            const std::vector<std::string>& contacts);
    [[nodiscard]] bool submit_message(const std::string& user_id,
            const std::vector<std::pair<int, signal_message>>& messages);

    [[nodiscard]] std::optional<std::vector<std::tuple<std::string, int, int, signal_message>>> retrieve_messages(
            const std::string& user_id);

private:
    tcp::resolver resolver;
    ssl::stream<tcp::socket> stream;
    boost::beast::flat_buffer buffer;
    http::request<http::string_body> req;
    http::response<http::string_body> res;
    tcp::resolver::results_type dns_results;
    client::database& client_db;

    std::string get_auth();
    std::string generate_random_auth_token();
    std::optional<boost::property_tree::ptree> parse_json_response(const std::string& body) const;
};

std::vector<std::string> retrieve_emails(const char *email, const char *password);
void export_email(const char *email, const char *password, const char *contents);

#endif /* end of include guard: CLIENT_NETWORK_H */
