#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
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
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "client_network.h"
#include "crypto.h"
#include "dh.h"
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

/*
 * Request is empty
 */
void client_network_session::request_verification_code(const std::string& email) {
    const auto target_str = [&email]() {
        const auto target_prefix = "/v1/accounts/email/code/";
        std::stringstream ss;
        ss << target_prefix;
        ss << email;
        return ss.str();
    }();

    req.method(http::verb::get);
    req.target(target_str);
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);
}

/*
 * Request is as follows:
 * {
 *   email: {email}
 *   signature: "{signature}",
 *   publicKey: "{public_key}",
 *   identityKey: "{identity_key}"
 * }
 */
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

    //This email should be replaced when client database is online
    ptr.add("email", "foobar@test.com");

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    spdlog::info("JSON output {}", ss.str());

    req.body() = ss.str();

    spdlog::info("Resulting body {}", req.body());

    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);
}

/*
 * Request is as follows:
 * {
 *   //Keys is for one-time key update
 *   keys: [
 *        "" : "{public_key}",
 *       ...]
 * }
 */
void client_network_session::register_prekeys(const uint64_t key_count) {
    req.method(http::verb::put);
    req.target("/v1/keys/");

    boost::property_tree::ptree ptr;

    for (uint64_t i = 0; i < key_count; ++i) {
        boost::property_tree::ptree child;

        //Ephemeral key needs to be stored in client database here
        crypto::DH_Keypair kp;

        std::stringstream ss;
        boost::archive::text_oarchive arch{ss};

        arch << kp.get_public();

        child.add("", ss.str());
        ptr.push_back(std::make_pair("", child));
    }

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);
}

void client_network_session::lookup_prekey(const std::string& user_id, const uint64_t device_id) {
    const auto target_str = [&user_id, device_id]() {
        const auto target_prefix = "/v1/keys/";
        std::stringstream ss;
        ss << target_prefix;
        ss << user_id;
        ss << '/';
        ss << device_id;
        return ss.str();
    }();

    req.method(http::verb::get);
    req.target(target_str);

    req.prepare_payload();

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
