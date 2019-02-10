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
#include "client_state.h"
#include "crypto.h"
#include "dh.h"
#include "logging.h"

//This will throw boost::system::system_error if any part of the connection fails
client_network_session::client_network_session(boost::asio::io_context& ioc, ssl::context& ctx,
        const char* dest_host, const char* dest_port, client::database& db) :
        resolver(ioc),
        stream(ioc, ctx), client_db(db) {
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
[[nodiscard]] bool client_network_session::request_verification_code(const std::string& email) {
    const auto target_str = [&email]() {
        const auto target_prefix = "/v1/accounts/email/code/";
        std::stringstream ss;
        ss << target_prefix;
        ss << email;
        return std::string{ss.str()};
    }();

    spdlog::debug("Request target string {}", target_str);

    req.method(http::verb::get);
    req.target(target_str);
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    return res.result() == http::status::ok;
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
[[nodiscard]] bool client_network_session::verify_verification_code(const uint64_t code) {
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

    //Clear the stringstream
    ss.str(std::string{});
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());

    return res.result() == http::status::ok;
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
[[nodiscard]] bool client_network_session::register_prekeys(const uint64_t key_count) {
    req.method(http::verb::put);
    req.target("/v1/keys/");

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree keys;

    for (uint64_t i = 0; i < key_count; ++i) {
        boost::property_tree::ptree child;

        //Ephemeral key needs to be stored in client database here
        crypto::DH_Keypair kp;

        std::stringstream ss;
        boost::archive::text_oarchive arch{ss};

        arch << kp.get_public();

        child.add("", ss.str());
        keys.push_back(std::make_pair("", child));
    }
    ptr.add_child("keys", keys);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    //Clear the stringstream
    ss.str(std::string{});
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());

    return res.result() == http::status::ok;
}

/*
 * Request is empty
 */
[[nodiscard]] bool client_network_session::lookup_prekey(const std::string& user_id, const uint64_t device_id) {
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

    //Clear the stringstream
    std::stringstream ss;
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());

    return res.result() == http::status::ok;
}

/*
 * Request is as follows:
 *  {
 *   "contacts": [ "{token}", "{token}", ..., "{token}" ]
 *  }
 */
[[nodiscard]] bool client_network_session::contact_intersection(const std::vector<std::string>& contacts) {
    req.method(http::verb::put);
    req.target("/v1/directory/tokens");

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree contact_data;

    for (const auto& email : contacts) {
        boost::property_tree::ptree child;

        const auto hash = crypto::hash_string(email);
        std::array<std::byte, 24> trunc_hash;
        std::copy(hash.begin(), hash.begin() + trunc_hash.size(), trunc_hash.begin());

        std::stringstream ss;
        boost::archive::text_oarchive arch{ss};

        arch << trunc_hash;

        child.add("", ss.str());
        contact_data.push_back(std::make_pair("", child));
    }

    ptr.add_child("contacts", contact_data);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    //Clear the stringstream
    ss.str(std::string{});
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());

    return res.result() == http::status::ok;
}

/*
 * Request is as follows:
 *
 * {
 *    message: [
 *      {
 *             dest_device: {destination_device_id},
 *             contents: "{serialized message}",
 *      },
 *      ...
 *    ]
 * }
 */
[[nodiscard]] bool client_network_session::submit_message(const std::string& user_id,
        const std::vector<std::pair<uint64_t, signal_message>>& messages) {
    const auto target_str = [&user_id]() {
        const auto target_prefix = "/v1/messages/";
        std::stringstream ss;
        ss << target_prefix;
        ss << user_id;
        return ss.str();
    }();

    req.method(http::verb::put);
    req.target(target_str);

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree message_data;

    for (const auto& [device_id, contents] : messages) {
        boost::property_tree::ptree child;

        std::stringstream ss;
        ss << device_id;
        child.add("dest_device", ss.str());

        //Clear the stringstream
        ss.str(std::string{});

        boost::archive::text_oarchive arch{ss};

        arch << contents;

        child.add("contents", ss.str());
        message_data.push_back(std::make_pair("", child));
    }

    ptr.add_child("message", message_data);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    //Clear the stringstream
    ss.str(std::string{});
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());
    return res.result() == http::status::ok;
}
