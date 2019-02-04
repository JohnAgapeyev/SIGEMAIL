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
    dns_results = resolver.resolve(dest_host, dest_port);
    //Connect to the domain
    boost::asio::connect(stream.next_layer(), dns_results.begin(), dns_results.end());
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

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::verify_verification_code(const uint64_t code) {
    const auto target_str = [code]() {
        const auto target_prefix = "/v1/accounts/code/";
        std::stringstream ss;
        ss << target_prefix;
        ss << code;
        return ss.str();
    }();

    req.method(http::verb::put);
    req.target(target_str);

    boost::property_tree::ptree ptr;

    ptr.add("foo.bar", "abc");
    ptr.add("foo.baz", "cde");

    boost::property_tree::ptree child;

    boost::property_tree::ptree child1;
    boost::property_tree::ptree child2;
    boost::property_tree::ptree child3;
    boost::property_tree::ptree child4;
    boost::property_tree::ptree child5;

    child1.put("", "1");
    child2.put("", "2");
    child3.put("", "3");
    child4.put("", "4");
    child5.put("", "5");

    child.push_back(std::make_pair("", child1));
    child.push_back(std::make_pair("", child2));
    child.push_back(std::make_pair("", child3));
    child.push_back(std::make_pair("", child4));
    child.push_back(std::make_pair("", child5));

    ptr.add_child("foo.foo", child);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    spdlog::info("JSON output {}", ss.str());

    req.body() = ss.str();

    spdlog::info("Resulting body {}", req.body());

    req.prepare_payload();

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
