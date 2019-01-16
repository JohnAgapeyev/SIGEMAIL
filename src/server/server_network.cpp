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
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "logging.h"
#include "server_network.h"

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
    handle_request(std::move(request), [this](auto&& msg) {
        // The lifetime of the message has to extend
        // for the duration of the async operation so
        // we use a shared_ptr to manage it.
        const auto sp = std::make_shared<std::remove_reference_t<decltype(msg)>>(std::move(msg));

        // Store a type-erased version of the shared
        // pointer in the class to keep it alive.
        result = sp;

        // Write the response
        http::async_write(stream, *sp,
                boost::asio::bind_executor(strand,
                        std::bind(&http_session::on_write, shared_from_this(),
                                std::placeholders::_1, sp->need_eof())));
    });
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
    // Send a SSL+TCP shutdown
    stream.shutdown();
    stream.lowest_layer().shutdown(tcp::socket::shutdown_both);
    stream.lowest_layer().close();

    // At this point the connection is closed gracefully
}

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<class Body, class Allocator, class Send>
void http_session::handle_request(
        http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) {
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
        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + what.to_string() + "'";
        res.prepare_payload();
        return res;
    };

    //Responds to a HEAD request
    const auto head_response = [&req](std::size_t size) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    };
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
    static constexpr auto version_prefix = "/v1/";
    static constexpr auto accounts_prefix = "accounts/";
    static constexpr auto keys_prefix = "keys/";
    static constexpr auto message_prefix = "messages";
    static constexpr auto contact_intersection = "directory/tokens";

    // Make sure we can handle the method
    if (req.method() != http::verb::get && req.method() != http::verb::head
            && req.method() != http::verb::put) {
        return send(bad_request("Unknown HTTP-method"));
    }

    auto target = req.target();

    // Request path must be absolute and not contain "..".
    if (target.empty() || target[0] != '/' || target.find("..") != std::string_view::npos) {
        return send(bad_request("Illegal request-target"));
    }

    //Check that the request targets the correct version endpoint
    //I doubt I'll ever need a v2, but this ensures I have that flexibility
    if (target.substr(0, strlen(version_prefix)).compare(version_prefix) != 0) {
        return send(not_found(req.target()));
    }

    //Move the view forward
    target.remove_prefix(strlen(version_prefix));

    //Ensure the target is large enough to hold the smallest valid target path
    if (target.size() < strlen(keys_prefix)) {
        return send(not_found(req.target()));
    }

    //Check the target for the accounts prefix
    if (target.substr(0, strlen(accounts_prefix)).compare(accounts_prefix) == 0) {
        target.remove_prefix(strlen(accounts_prefix));

        const auto code_index = target.find("code/");

        if (code_index == 0) {
            //Request verification code
            if (req.method() != http::verb::put) {
                return send(bad_request("Wrong request method"));
            }
            spdlog::info("Confirm verification message");
        } else if (code_index == 6) {
            if (target.substr(0, 6).compare("email/") != 0) {
                //Malformed target
                return send(not_found(req.target()));
            }
            if (req.method() != http::verb::get && req.method() != http::verb::head) {
                return send(bad_request("Wrong request method"));
            }
            if (req.method() == http::verb::head) {
                return send(head_response(0));
            }
            //Confirm verification code
            spdlog::info("Request verification message");
        } else {
            //"code/" was not found, therefore it is not a valid target
            return send(not_found(req.target()));
        }
        //Check for keys prefix
    } else if (target.substr(0, strlen(keys_prefix)).compare(keys_prefix) == 0) {
        target.remove_prefix(strlen(keys_prefix));
        if (target.empty()) {
            if (req.method() != http::verb::put) {
                return send(bad_request("Wrong request method"));
            }
            //PreKey registration
            spdlog::info("Key registration message");
        } else {
            if (req.method() != http::verb::get && req.method() != http::verb::head) {
                return send(bad_request("Wrong request method"));
            }
            if (req.method() == http::verb::head) {
                return send(head_response(0));
            }
            //Request contact PreKeys
            spdlog::info("Key lookup message");
        }
        //Check for message prefix
    } else if (target.substr(0, strlen(message_prefix)).compare(message_prefix) == 0) {
        if (req.method() != http::verb::put) {
            return send(bad_request("Wrong request method"));
        }
        spdlog::info("Message message");
        //Check for contact intersection target
    } else if (target.compare(contact_intersection) == 0) {
        if (req.method() != http::verb::put) {
            return send(bad_request("Wrong request method"));
        }
        //Handle contact intersection request
        spdlog::info("Contact intersection");
    } else {
        return send(not_found(req.target()));
    }

    // Attempt to open the file
    boost::beast::error_code ec;
    http::file_body::value_type body;
    //body.open(path.c_str(), boost::beast::file_mode::scan, ec);

    // Handle the case where the file doesn't exist
    if (ec == boost::system::errc::no_such_file_or_directory) {
        return send(not_found(req.target()));
    }

    // Handle an unknown error
    if (ec) {
        return send(server_error(ec.message()));
    }

    // Cache the size since we need it after the move
    const auto size = body.size();

    // Respond to HEAD request
    if (req.method() == http::verb::head) {
        return send(head_response(0));
    }
    if (req.method() == http::verb::get) {
        // Respond to GET request
        http::response<http::file_body> res{std::piecewise_construct,
                std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }
    if (req.method() == http::verb::put) {
        //Put Request
    }
    //Unknown/unsupported request
}

template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::request_verification_code(const std::string_view email) const {
    //Foobar
}
template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::verify_verification_code(const std::string_view code) const {
    //Foobar
}
template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::register_prekeys() const {
    //Foobar
}
template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::lookup_prekey(
                const std::string_view user, const std::string_view device) const {
    //Foobar
}
template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::contact_intersection() const {
    //Foobar
}

template<typename Allocator>
const http::response<http::basic_string_body<Allocator>, http::basic_fields<Allocator>>
        http_session::submit_message() const {
    //Foobar
}
