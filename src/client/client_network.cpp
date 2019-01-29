#include <boost/asio/bind_executor.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "client_network.h"
#include "logging.h"

//This will throw boost::system::system_error if any part of the connection fails
client_network_session::client_network_session(boost::asio::io_context& ioc, ssl::context& ctx,
        const char* dest_host, const char* dest_port) :
        resolver(ioc),
        stream(ioc, ctx) {
    //Set default fields that will always be present
    req.set(http::field::host, dest_host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    const auto results = resolver.resolve(dest_host, dest_port);
    //Connect to the domain
    boost::asio::connect(stream.next_layer(), results.begin(), results.end());
    // Perform the SSL handshake
    stream.handshake(ssl::stream_base::client);
}

//This currently has some sort of error going on for stream shutdown, need to diagnose and handle
client_network_session::~client_network_session() {
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
}

void client_network_session::request_verification_code() {
    req.method(http::verb::get);
    req.target("/v1/accounts/email/code/foobar@test.com");

    boost::property_tree::ptree ptr;

    ptr.put("foo", "abc");

#if 0
    ptr.put("foo.bar", "cde");

    boost::property_tree::ptree child;

    child.put_value("1");
    child.put_value("2");
    child.put_value("3");
    child.put_value("4");
    child.put_value("5");

    ptr.add_child("foo.bar.baz", child);
#endif

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);
    req.body() = ss.str();

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::verify_verification_code() {
    req.method(http::verb::put);
    req.target("/v1/accounts/code/foobar@test.com");

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::register_prekeys() {
    req.method(http::verb::put);
    req.target("/v1/keys/");

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::lookup_prekey() {
    req.method(http::verb::get);
    req.target("/v1/keys/foobar@test.com/123");

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::contact_intersection() {
    req.method(http::verb::put);
    req.target("/v1/directory/tokens");

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::submit_message() {
    req.method(http::verb::put);
    req.target("/v1/messages/foobar@test.com");

    http::write(stream, req);
    http::read(stream, buffer, res);
}
