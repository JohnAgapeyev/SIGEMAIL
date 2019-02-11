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
#include <random>

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
    stream.lowest_layer().shutdown(boost::asio::socket_base::shutdown_both, ec);
    if (ec) {
        spdlog::error("Client shutdown error: {}", ec.message());
    }
    stream.lowest_layer().close(ec);
    if (ec) {
        spdlog::error("Client shutdown error: {}", ec.message());
    }
}

/*
 * Request is empty
 */
[[nodiscard]] bool client_network_session::request_verification_code(const std::string& email) {
    req.clear();
    req.body() = "";
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
 *   identity_key: "{identity_key}"
 *   pre_key: "{public_key}",
 *   signature: "{signature}",
 * }
 */
[[nodiscard]] bool client_network_session::verify_verification_code(const std::string& email, const uint64_t code) {
    req.clear();
    req.body() = "";
    const auto target_str = [code]() {
        const auto target_prefix = "/v1/accounts/code/";
        std::stringstream ss;
        ss << target_prefix;
        ss << code;
        return ss.str();
    }();

    std::string auth_token = generate_random_auth_token();

    const auto auth_str = [&email, &auth_token]() {
        const auto auth_prefix = "Basic ";
        std::stringstream ss;
        ss << auth_prefix << email << ':' << auth_token;
        return ss.str();
    }();

    req.method(http::verb::put);
    req.target(target_str);
    req.set(http::field::www_authenticate, auth_str);

    boost::property_tree::ptree ptr;

    std::stringstream ss;

    crypto::DH_Keypair identity_keypair;

    {
        boost::archive::text_oarchive arch{ss};
        arch << identity_keypair.get_public();
    }

    ptr.add("identity_key", ss.str());

    crypto::DH_Keypair pre_key;

    ss.str(std::string{});

    {
        boost::archive::text_oarchive arch{ss};
        arch << pre_key.get_public();
    }

    ptr.add("pre_key", ss.str());

    crypto::signature key_sig = crypto::sign_key(identity_keypair, pre_key.get_public());

    ss.str(std::string{});

    {
        boost::archive::text_oarchive arch{ss};
        arch << key_sig;
    }

    ptr.add("signature", ss.str());

    ss.str(std::string{});

    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();

    //Clear the stringstream
    ss.str(std::string{});
    ss << req;
    spdlog::info("Sending request \n{}", ss.str());

    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    //Clear the stringstream
    ss.str(std::string{});
    ss << res;
    spdlog::debug("Got a server response:\n{}", ss.str());

    if (res.result() == http::status::ok) {
        //Verification succeeded
        //Device ID will need to be grabbed from the response
        client_db.save_registration(email, 1, auth_token, identity_keypair, pre_key);
        return true;
    }
    return false;
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
    req.clear();
    req.body() = "";
    req.method(http::verb::put);
    req.target("/v1/keys/");
    req.set(http::field::www_authenticate, get_auth());

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree keys;

    for (uint64_t i = 0; i < key_count; ++i) {
        boost::property_tree::ptree child;

        //Ephemeral key needs to be stored in client database here
        crypto::DH_Keypair kp;

        std::stringstream ss;
        boost::archive::text_oarchive arch{ss};

        arch << kp.get_public();

        child.put("", ss.str());
        keys.push_back(std::make_pair("", child));
    }
    ptr.add_child("keys", keys);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    //Clear the stringstream
    ss.str(std::string{});
    ss << req;
    spdlog::debug("Sending request \n{}", ss.str());

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
    req.clear();
    req.body() = "";
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
    req.set(http::field::www_authenticate, get_auth());

    req.prepare_payload();

    //Clear the stringstream
    std::stringstream ss;
    ss << req;
    spdlog::debug("Sending client request\n{}", ss.str());

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
 *  {
 *   "contacts": [ "{token}", "{token}", ..., "{token}" ]
 *  }
 */
[[nodiscard]] bool client_network_session::contact_intersection(const std::vector<std::string>& contacts) {
    req.clear();
    req.body() = "";
    req.method(http::verb::put);
    req.target("/v1/directory/tokens");
    req.set(http::field::www_authenticate, get_auth());

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

        child.put("", ss.str());
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
    req.clear();
    req.body() = "";
    const auto target_str = [&user_id]() {
        const auto target_prefix = "/v1/messages/";
        std::stringstream ss;
        ss << target_prefix;
        ss << user_id;
        return ss.str();
    }();

    req.method(http::verb::put);
    req.target(target_str);
    req.set(http::field::www_authenticate, get_auth());

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

std::string client_network_session::get_auth() {
    const auto [user_id, device_id, auth_token, identity, pre_key] = client_db.get_self_data();
    std::stringstream ss;
    ss << "Basic " << user_id << ':' << auth_token;
    return ss.str();
}

std::string client_network_session::generate_random_auth_token() {
    static const std::vector<char> charset{
        '0','1','2','3','4',
        '5','6','7','8','9',
        'A','B','C','D','E','F',
        'G','H','I','J','K',
        'L','M','N','O','P',
        'Q','R','S','T','U',
        'V','W','X','Y','Z',
        'a','b','c','d','e','f',
        'g','h','i','j','k',
        'l','m','n','o','p',
        'q','r','s','t','u',
        'v','w','x','y','z'
    };
    static std::default_random_engine rng(std::random_device{}());
    static std::uniform_int_distribution<> dist(0, charset.size()-1);
    static const auto gen_func = [](){return charset[dist(rng)];};
    static constexpr auto auth_len = 32;

    std::array<char, auth_len> out;
    std::generate_n(out.begin(), auth_len, gen_func);
    return std::string{out.data(), out.size()};
}
