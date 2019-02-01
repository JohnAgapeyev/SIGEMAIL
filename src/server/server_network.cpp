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
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "error.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

void http_session::run() {
    // Make sure we run on the strand
    if (!strand.running_in_this_thread()) {
        return boost::asio::post(boost::asio::bind_executor(
                strand, std::bind(&http_session::run, shared_from_this())));
    }

    spdlog::debug("Starting SSL Handshake");

    // Perform the SSL handshake
    stream.async_handshake(ssl::stream_base::server,
            boost::asio::bind_executor(strand,
                    std::bind(&http_session::on_handshake, shared_from_this(),
                            std::placeholders::_1)));
}

void http_session::on_handshake(boost::system::error_code ec) {
    if (ec) {
        //Handshake failed
        spdlog::error("SSL Handshake failed");
        return;
    }
    stream.lowest_layer().set_option(boost::asio::socket_base::keep_alive{true});
    do_read();
}

void http_session::do_read() {
    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    request = {};

    // Read a request
    http::async_read(stream, buffer, request,
            boost::asio::bind_executor(strand,
                    std::bind(&http_session::on_read, shared_from_this(), std::placeholders::_1)));
}

void http_session::on_read(boost::system::error_code ec) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    // This means they closed the connection
    if (ec == http::error::end_of_stream) {
        do_close();
        return;
    }

    if (ec) {
        spdlog::error("Read failed");
        return;
    }

    // Send the response
    const auto msg = handle_request(std::move(request));

    // The lifetime of the message has to extend
    // for the duration of the async operation so
    // we use a shared_ptr to manage it.
    const auto sp = std::make_shared<std::remove_reference_t<decltype(msg)>>(std::move(msg));

    // Store a type-erased version of the shared
    // pointer in the class to keep it alive.
    result = std::reinterpret_pointer_cast<const void>(sp);

    // Write the response
    http::async_write(stream, *sp,
            boost::asio::bind_executor(strand,
                    std::bind(&http_session::on_write, shared_from_this(), std::placeholders::_1,
                            sp->need_eof())));
}

void http_session::on_write(boost::system::error_code ec, bool close) {
    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    if (ec) {
        spdlog::error("Write failed");
        return;
    }

    if (close) {
        // This means we should close the connection, usually because the response indicated the "Connection: close" semantic.
        do_close();
        return;
    }

    // Read another request
    do_read();
}

void http_session::do_close() {
    boost::system::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }
    if (ec) {
        spdlog::error("Client shutdown error: {}", ec.message());
    }
    stream.lowest_layer().shutdown(boost::asio::socket_base::shutdown_both);
    stream.lowest_layer().close();

    // At this point the connection is closed gracefully
    is_closed = true;
}

/**
 * List of endpoints:
 *
 * Request verification code:
 * GET /v1/accounts/email/code/{number}
 *
 * Confirm verification code:
 * PUT /v1/accounts/code/{verification_code}
 *
 * Register Prekeys
 * PUT /v1/keys/
 *
 * Contact Intersection
 * PUT /v1/directory/tokens
 *
 * Get Contact PreKey
 * GET /v1/keys/{number}/{device_id}
 *
 * Submit Message
 * PUT /v1/messages/{destination_number}
 *
 * These are based on the examples given at:
 * https://github.com/signalapp/Signal-Server/wiki/API-Protocol
 *
 * I will be modifying it slightly for my own needs, primarily in regards to the message formatting
 */
const http::response<http::string_body> http_session::handle_request(
        http::request<http::string_body>&& req) {
    static constexpr auto version_prefix = "/v1/";
    static constexpr auto accounts_prefix = "accounts/";
    static constexpr auto keys_prefix = "keys/";
    static constexpr auto message_prefix = "messages";
    static constexpr auto contact_intersection_target = "directory/tokens";

    // Make sure we can handle the method
    if (req.method() != http::verb::get && req.method() != http::verb::put) {
        return bad_request("Unknown HTTP-method");
    }

    auto target = std::string_view{req.target().to_string()};

    // Request path must be absolute and not contain "..".
    if (target.empty() || target[0] != '/' || target.find("..") != std::string_view::npos) {
        return bad_request("Illegal request-target");
    }

    //Check that the request targets the correct version endpoint
    //I doubt I'll ever need a v2, but this ensures I have that flexibility
    if (target.substr(0, strlen(version_prefix)).compare(version_prefix) != 0) {
        return not_found(std::string{req.target()});
    }

    //Move the view forward
    target.remove_prefix(strlen(version_prefix));

    //Ensure the target is large enough to hold the smallest valid target path
    if (target.size() < strlen(keys_prefix)) {
        return not_found(std::string(req.target()));
    }

    //Check the target for the accounts prefix
    if (target.substr(0, strlen(accounts_prefix)).compare(accounts_prefix) == 0) {
        target.remove_prefix(strlen(accounts_prefix));

        const auto code_str = "code/";

        const auto code_index = target.find(code_str);

        if (code_index == 0) {
            //Request verification code
            if (req.method() != http::verb::put) {
                return bad_method();
            }
            //Remaining target should be the code
            target.remove_prefix(strlen(code_str));
            spdlog::info("Confirm verification message");
            return verify_verification_code(std::move(req), target);
        } else if (code_index == 6) {
            const auto email_substr = "email/";
            if (target.substr(0, 6).compare(email_substr) != 0) {
                //Malformed target
                return not_found(std::string(req.target()));
            }
            if (req.method() != http::verb::get) {
                return bad_method();
            }

            //After this, the remaining target should only be the email address
            target.remove_prefix(strlen(email_substr));

            //Confirm verification code
            spdlog::info("Request verification message");
            return request_verification_code(std::move(req), target);
        } else {
            //"code/" was not found, therefore it is not a valid target
            return not_found(std::string(req.target()));
        }
        //Check for keys prefix
    } else if (target.substr(0, strlen(keys_prefix)).compare(keys_prefix) == 0) {
        target.remove_prefix(strlen(keys_prefix));
        if (target.empty()) {
            if (req.method() != http::verb::put) {
                return bad_method();
            }
            //PreKey registration
            spdlog::info("Key registration message");
            return register_prekeys(std::move(req));
        } else {
            if (req.method() != http::verb::get) {
                return bad_method();
            }
            //Request contact PreKeys
            spdlog::info("Key lookup message");
            return lookup_prekey(std::move(req));
        }
        //Check for message prefix
    } else if (target.substr(0, strlen(message_prefix)).compare(message_prefix) == 0) {
        if (req.method() != http::verb::put) {
            return bad_method();
        }
        spdlog::info("Message message");
        return submit_message(std::move(req));
        //Check for contact intersection target
    } else if (target.compare(contact_intersection_target) == 0) {
        if (req.method() != http::verb::put) {
            return bad_method();
        }
        //Handle contact intersection request
        spdlog::info("Contact intersection");
        return contact_intersection(std::move(req));
    } else {
        return not_found(std::string(req.target()));
    }
}

//This functions does not need a verification confirmation, since it is how they are originally requested
const http::response<http::string_body> http_session::request_verification_code(
        http::request<http::string_body>&& req, const std::string_view email) const {
    if (!req.body().empty()) {
        //Expected an empty request, but received data
        return bad_request("Expected an empty request body");
    }
    //Email is not valid format
    if (email.empty() || email.size() > 254 || email.find('@') == std::string_view::npos) {
        return bad_request("Invalid email address format");
    }

    //This needs to be randomly generated, decently large, and sent via SMTP to the address
    uint64_t registration_code = 1;

    server_db.add_registration_code(email, registration_code);

    return http_ok();
}

const http::response<http::string_body> http_session::verify_verification_code(
        http::request<http::string_body>&& req, const std::string_view reg_code) const {
    if (!confirm_authentication(req[http::field::www_authenticate].to_string())) {
        //Authentication code verification failed
        return unauthorized();
    }

    const auto ptr = parse_json_request(req.body());
    if (!ptr) {
        return bad_json();
    }

    try {
        const int code = std::stoi(std::string{reg_code.data(), reg_code.size()});
        const auto email = server_db.confirm_registration_code(code);
        if (email.empty()) {
            //Code was bad
            return forbidden();
        }
    } catch (const db_error&) {
        //Bad request
        return server_error("Bad database lookup");
    } catch (const std::exception&) {
        //Bad request
        return bad_request("Code is not a number");
    }

    //Now parse the body contents

    return http_ok();
}

const http::response<http::string_body> http_session::register_prekeys(
        http::request<http::string_body>&& req) const {
    const auto ptr = parse_json_request(req.body());
    if (!ptr) {
        return bad_json();
    }
    if (!confirm_authentication(req[http::field::www_authenticate].to_string())) {
        //Authentication code verification failed
        return unauthorized();
    }
    return http_ok();
}

const http::response<http::string_body> http_session::lookup_prekey(
        http::request<http::string_body>&& req) const {
    const auto ptr = parse_json_request(req.body());
    if (!ptr) {
        return bad_json();
    }
    if (!confirm_authentication(req[http::field::www_authenticate].to_string())) {
        //Authentication code verification failed
        return unauthorized();
    }
    return http_ok();
}

const http::response<http::string_body> http_session::contact_intersection(
        http::request<http::string_body>&& req) const {
    const auto ptr = parse_json_request(req.body());
    if (!ptr) {
        return bad_json();
    }
    if (!confirm_authentication(req[http::field::www_authenticate].to_string())) {
        //Authentication code verification failed
        return unauthorized();
    }
    return http_ok();
}

const http::response<http::string_body> http_session::submit_message(
        http::request<http::string_body>&& req) const {
    const auto ptr = parse_json_request(req.body());
    if (!ptr) {
        return bad_json();
    }
    if (!confirm_authentication(req[http::field::www_authenticate].to_string())) {
        //Authentication code verification failed
        return unauthorized();
    }
    return http_ok();
}

[[nodiscard]] bool http_session::confirm_authentication(std::string_view www_auth) const {
    if (www_auth.empty()) {
        //No WWW-Authenticate header
        return false;
    }

    size_t delim_loc = www_auth.find_first_of(' ');
    if (delim_loc == 0 || delim_loc == std::string_view::npos || delim_loc == www_auth.size()) {
        //Space delimeter is in an unexpected spot
        return false;
    }

    if (www_auth.substr(0, delim_loc - 1).compare("Basic") != 0) {
        //Auth type is not Basic, therefore unsupported
        return false;
    }

    //Drop the auth type from the string
    www_auth.remove_prefix(delim_loc);

    /*
     * Alright, so there will be no base64 involved with the auth token.
     * My reason for this is that I'm already limiting things to ASCII
     * Base64 won't prevent someone's email address from having a colon char in it, which is still a problem.
     * I can treat the rest of the text after the colon as the "password", so escaping those kinds of chars isn't necessary
     */

    delim_loc = www_auth.find_first_of(':');
    if (delim_loc == 0 || delim_loc == std::string_view::npos || delim_loc == www_auth.size()) {
        //Colon delimeter is in an unexpected spot
        return false;
    }

    const auto user_id = www_auth.substr(0, delim_loc - 1);
    const auto password = www_auth.substr(delim_loc + 1);

    return server_db.confirm_auth_token(user_id, password);
}

std::optional<boost::property_tree::ptree> http_session::parse_json_request(
        const std::string& body) const {
    try {
        std::stringstream ss{body};
        boost::property_tree::ptree ptr;
        boost::property_tree::read_json(ss, ptr);
        spdlog::debug("Received request contents {}", ss.str());
        return ptr;
    } catch (const boost::property_tree::json_parser_error& e) {
        spdlog::error("Failed to convert JSON to Property Tree: {}", e.what());
        return std::nullopt;
    }
}

const http::response<http::string_body> http_session::not_found(const std::string& target) const {
    http::response<http::string_body> res{http::status::not_found, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(false);
    res.body() = "The resource '" + target + "' was not found.";
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::server_error(const std::string& what) const {
    http::response<http::string_body> res{http::status::internal_server_error, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(false);
    res.body() = "An error occurred: '" + what + "'";
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::bad_request(const std::string& why) const {
    http::response<http::string_body> res{http::status::bad_request, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(false);
    res.body() = why;
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::unauthorized() const {
    http::response<http::string_body> res{http::status::unauthorized, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(false);
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::forbidden() const {
    http::response<http::string_body> res{http::status::forbidden, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(false);
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::http_ok() const {
    http::response<http::string_body> res{http::status::ok, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(true);
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::bad_json() const {
    http::response<http::string_body> res{http::status::unsupported_media_type, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(false);
    res.prepare_payload();
    return res;
}

const http::response<http::string_body> http_session::bad_method() const {
    http::response<http::string_body> res{http::status::method_not_allowed, 10};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(false);
    res.prepare_payload();
    return res;
}
