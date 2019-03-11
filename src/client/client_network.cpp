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
#include <curl/curl.h>
#include <cstdint>
#include <cstdlib>
#include <optional>
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

size_t new_email_index = 0;
std::string retrieved_email;
bool read_active = false;

size_t parse_examine_id(void *buffer, size_t size, size_t nmemb, void *userp) {
    (void)userp;
    std::string resp_str{static_cast<char *>(buffer), nmemb};

    spdlog::info("Response {}", resp_str);

    std::string last_word = resp_str.substr(resp_str.find_last_of(' ') + 1);
    spdlog::info("Last {}", last_word);

    if (last_word == "EXISTS\r\n") {
        std::stringstream ss{resp_str};

        std::string size_tok;

        //Drop the first word, and store the number in size_tok
        ss >> size_tok >> size_tok;

        spdlog::info("Size tok {}", size_tok);

        try {
            new_email_index = std::stoull(size_tok);
        } catch(const std::exception& e) {
            spdlog::error("Failed to convert id token {}", e.what());
            new_email_index = -1;
        }
    }
    return size * nmemb;
}

size_t parse_email_plaintext(void *buffer, size_t size, size_t nmemb, void *userp) {
    (void)userp;
    std::string resp_str{static_cast<char *>(buffer), nmemb};

    if (read_active) {
        retrieved_email.append(resp_str);
        return size * nmemb;
    }

    spdlog::info("Email Response {}", resp_str);

    const auto content_header = "Content-Type: text/plain; charset=\"UTF-8\"\r\n";
    const auto content_index = resp_str.find(content_header);

    resp_str.erase(0, content_index + strlen(content_header));

    read_active = true;
    retrieved_email.append(resp_str);
    return size * nmemb;
}

void retrieve_emails(const char *email, const char *password) {
    new_email_index = 0;

    retrieved_email.clear();
    read_active = false;

    CURLcode res = CURLE_OK;

    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, email);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);

        curl_easy_setopt(curl, CURLOPT_URL, "imaps://imap.gmail.com:993/SIGEMAIL/;UID=1:*");
        //curl_easy_setopt(curl, CURLOPT_URL, "imaps://imap.gmail.com:993");
        //curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "EXAMINE INBOX");
        //curl_easy_setopt(curl, CURLOPT_URL, "imaps://imap.gmail.com:993");
        //curl_easy_setopt(curl, CURLOPT_URL, "imaps://imap.gmail.com:993/INBOX/;UID=*");

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        //curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &parse_examine_id);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &parse_email_plaintext);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            spdlog::error("curl_easy_perform() failed: {}", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    } else {
        spdlog::error("Failed to init curl");
    }

    //spdlog::info("Most recent message index {}", new_email_index);
    spdlog::info("Email contents {}", retrieved_email);
}

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
 * Request is as follows:
 * {
 *   email: "{email address}"
 *   password: "{password}"
 * }
 *
 * I don't like doing this, but I can't find a good way of sending emails
 * to GMail without going badly out of scope, or without the password
 */
[[nodiscard]] bool client_network_session::request_verification_code(const std::string& email, const std::string& password) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
    const auto target_str = [&email]() {
        const auto target_prefix = "/v1/accounts/email/code/";
        std::stringstream ss;
        ss << target_prefix;
        ss << email;
        return std::string{ss.str()};
    }();

    req.method(http::verb::get);
    req.target(target_str);

    boost::property_tree::ptree ptr;

    ptr.add("email", email);
    ptr.add("password", password);

    std::stringstream ss;

    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();

    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

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
[[nodiscard]] bool client_network_session::verify_verification_code(const std::string& email, const std::string& password, const int code) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
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
    req.prepare_payload();

    spdlog::debug("Sending request \n{}", req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    if (res.result() != http::status::ok) {
        return false;
    }

    const auto resp_ptr = parse_json_response(res.body());
    if (!resp_ptr) {
        //Got a badly formattted server response
        return false;
    }

    const auto did = resp_ptr->get_child_optional("device_id");
    if (!did) {
        //Got a badly formattted server response
        return false;
    }
    const auto device_id_str = did->get_value<std::string>();

    int device_id;
    try {
        device_id = std::stoi(device_id_str);
    } catch (const std::exception&) {
        //Bad request
        return false;
    }

    //Verification succeeded
    client_db.save_registration(email, device_id, auth_token, password, identity_keypair, pre_key);

    //Add self records to other tables
    client_db.add_user_record(email);
    client_db.add_device_record(email, device_id, identity_keypair.get_public());

    return true;
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
[[nodiscard]] bool client_network_session::register_prekeys(const int key_count) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
    req.method(http::verb::put);
    req.target("/v1/keys/");
    req.set(http::field::www_authenticate, get_auth());

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree keys;

    for (int i = 0; i < key_count; ++i) {
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

    spdlog::debug("Sending request \n{}", req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    return res.result() == http::status::ok;
}

/*
 * Request is empty
 */
[[nodiscard]] std::optional<std::vector<std::tuple<int, crypto::public_key, crypto::public_key, std::optional<crypto::public_key>>>> client_network_session::lookup_prekey(const std::string& user_id, const int device_id) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
    const auto target_str = [&user_id, device_id]() {
        const auto target_prefix = "/v1/keys/";
        std::stringstream ss;
        ss << target_prefix;
        ss << user_id;
        ss << '/';
        if (device_id == -1) {
            ss << '*';
        } else {
            ss << device_id;
        }
        return ss.str();
    }();

    req.method(http::verb::get);
    req.target(target_str);
    req.set(http::field::www_authenticate, get_auth());

    req.prepare_payload();

    spdlog::debug("Sending client request\n{}", req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    if (res.result() != http::status::ok) {
        return std::nullopt;
    }

    const auto ptr = parse_json_response(res.body());
    if (!ptr) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    const auto keys = ptr->get_child_optional("keys");
    if (!keys) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    std::vector<std::tuple<int, crypto::public_key, crypto::public_key, std::optional<crypto::public_key>>> key_data;

    for (const auto& [key, value] : *keys) {
        const auto key_child = value.get_child_optional("");
        if (!key_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto device_id_str = key_child->get_child("device_id").get_value<std::string>();
        const auto identity_str = key_child->get_child("identity").get_value<std::string>();
        const auto prekey_str = key_child->get_child("prekey").get_value<std::string>();
        const auto signature_str = key_child->get_child("signature").get_value<std::string>();

        int device_id;
        try {
            device_id = std::stoi(device_id_str);
        } catch (const std::exception&) {
            //Bad request
            return std::nullopt;
        }

        std::stringstream ss{identity_str};

        crypto::public_key identity_pubkey;

        {
            boost::archive::text_iarchive arch{ss};
            arch >> identity_pubkey;
        }

        ss.str(prekey_str);

        crypto::public_key prekey_pubkey;

        {
            boost::archive::text_iarchive arch{ss};
            arch >> prekey_pubkey;
        }

        ss.str(signature_str);

        crypto::signature signature;

        {
            boost::archive::text_iarchive arch{ss};
            arch >> signature;
        }

        if (!crypto::verify_signed_key(signature, prekey_pubkey, identity_pubkey)) {
            //Key signature failed to verify
            return std::nullopt;
        }

        std::optional<crypto::public_key> one_time_key;
        try {
            const auto one_time_str = key_child->get_child("one_time").get_value<std::string>();
            ss.str(one_time_str);
            crypto::public_key one_time;
            {
                boost::archive::text_iarchive arch{ss};
                arch >> one_time;
            }
            one_time_key = one_time;
        } catch(const boost::property_tree::ptree_error&) {
            //Ignore the error, there is no one-time key
            one_time_key = std::nullopt;
        } catch(...) {
            //Unknown error on the one time key
            spdlog::error("Hit an unknown error on reading one time key from lookup message");
            one_time_key = std::nullopt;
        }

        key_data.emplace_back(device_id, identity_pubkey, prekey_pubkey, one_time_key);
    }

    return key_data;
}

/*
 * Request is as follows:
 *  {
 *   "contacts": [ "{token}", "{token}", ..., "{token}" ]
 *  }
 */
[[nodiscard]] std::optional<std::vector<std::string>> client_network_session::contact_intersection(const std::vector<std::string>& contacts) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
    req.method(http::verb::put);
    req.target("/v1/directory/tokens");
    req.set(http::field::www_authenticate, get_auth());

    boost::property_tree::ptree ptr;
    boost::property_tree::ptree contact_data;

    std::map<std::array<std::byte, 24>, std::string> contact_hash_map;

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

        contact_hash_map.emplace(trunc_hash, email);
    }

    ptr.add_child("contacts", contact_data);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    spdlog::debug("Sending client request \n{}", req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    if (res.result() != http::status::ok) {
        return std::nullopt;
    }

    const auto resp_ptr = parse_json_response(res.body());
    if (!resp_ptr) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    const auto contact_ptr = resp_ptr->get_child_optional("contacts");
    if (!contact_ptr) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    std::vector<std::string> intersection;
    std::vector<std::array<std::byte, 24>> intersection_hashes;

    for (const auto& [key, value] : *contact_ptr) {
        const auto hash_child = value.get_child_optional("");
        if (!hash_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto trunc_hash_str = hash_child->get_value<std::string>();

        std::array<std::byte, 24> trunc_hash;

        std::stringstream ss{trunc_hash_str};
        boost::archive::text_iarchive arch{ss};

        arch >> trunc_hash;

        intersection_hashes.emplace_back(std::move(trunc_hash));
    }

    for (const auto& hash : intersection_hashes) {
        decltype(contact_hash_map.begin()) hash_it;
        if ((hash_it = contact_hash_map.find(hash)) == contact_hash_map.end()) {
            //Server responded with a hash that we don't have
            return std::nullopt;
        }
        intersection.emplace_back(hash_it->second);
    }

    return intersection;
}

/*
 * Request is as follows:
 *
 * {
 *    messages: [
 *      {
 *             from_user: {sender_email},
 *             from_id: {sender_device_id},
 *             dest_id: {destination_device_id},
 *             contents: "{serialized message}",
 *      },
 *      ...
 *    ]
 * }
 */
[[nodiscard]] bool client_network_session::submit_message(const std::string& user_id,
        const std::vector<std::pair<int, signal_message>>& messages) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
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

    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey] = client_db.get_self_data();

    for (const auto& [device_id, contents] : messages) {
        boost::property_tree::ptree child;

        child.add("from_user", self_email);

        std::stringstream ss;
        ss << self_device_id;
        child.add("from_id", ss.str());

        //Clear the stringstream
        ss.str(std::string{});
        ss << device_id;
        child.add("dest_id", ss.str());

        //Clear the stringstream
        ss.str(std::string{});

        boost::archive::text_oarchive arch{ss};

        arch << contents;

        child.add("contents", ss.str());
        message_data.push_back(std::make_pair("", child));
    }

    ptr.add_child("messages", message_data);

    std::stringstream ss;
    boost::property_tree::write_json(ss, ptr);

    req.body() = ss.str();
    req.prepare_payload();

    spdlog::debug("Sending a client request \n{}", req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    return res.result() == http::status::ok;
}

[[nodiscard]] std::optional<std::vector<std::tuple<std::string, int, int, signal_message>>> client_network_session::retrieve_messages(const std::string& user_id) {
    req.clear();
    req.body() = "";
    res.clear();
    res.body() = "";
    const auto target_str = [&user_id]() {
        const auto target_prefix = "/v1/messages/";
        std::stringstream ss;
        ss << target_prefix;
        ss << user_id;
        return ss.str();
    }();

    req.method(http::verb::get);
    req.target(target_str);
    req.set(http::field::www_authenticate, get_auth());

    req.body() = "";
    req.prepare_payload();

    http::write(stream, req);
    http::read(stream, buffer, res);

    spdlog::debug("Got a server response:\n{}", res);

    if (res.result() != http::status::ok) {
        return std::nullopt;
    }

    const auto resp_ptr = parse_json_response(res.body());
    if (!resp_ptr) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    const auto message_ptr = resp_ptr->get_child_optional("messages");
    if (!message_ptr) {
        //Got a badly formattted server response
        return std::nullopt;
    }

    std::vector<std::tuple<std::string, int, int, signal_message>> messages;

    for (const auto& [key, value] : *message_ptr) {
        const auto email_child = value.get_child_optional("from_user");
        if (!email_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto from_email = email_child->get_value<std::string>();

        const auto from_id_child = value.get_child_optional("from_id");
        if (!from_id_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto from_device_id_str = from_id_child->get_value<std::string>();

        int from_device_id;
        try {
            from_device_id = std::stoi(from_device_id_str);
        } catch(const std::exception&) {
            //Failed to convert device id to int
            return std::nullopt;
        }
        const auto dest_id_child = value.get_child_optional("dest_id");
        if (!dest_id_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto dest_device_id_str = dest_id_child->get_value<std::string>();

        int dest_device_id;
        try {
            dest_device_id = std::stoi(dest_device_id_str);
        } catch(const std::exception&) {
            //Failed to convert device id to int
            return std::nullopt;
        }

        const auto contents_child = value.get_child_optional("contents");
        if (!contents_child) {
            //Got a badly formattted server response
            return std::nullopt;
        }
        const auto contents_str = contents_child->get_value<std::string>();

        signal_message m;

        std::stringstream ss{contents_str};
        boost::archive::text_iarchive arch{ss};

        arch >> m;

        messages.emplace_back(from_email, from_device_id, dest_device_id, std::move(m));
    }

    return messages;
}

std::string client_network_session::get_auth() {
    const auto [user_id, device_id, auth_token, email_pass, identity, pre_key] = client_db.get_self_data();
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

std::optional<boost::property_tree::ptree> client_network_session::parse_json_response(
        const std::string& body) const {
    try {
        std::stringstream ss{body};
        boost::property_tree::ptree ptr;
        boost::property_tree::read_json(ss, ptr);
        return ptr;
    } catch (const boost::property_tree::json_parser_error& e) {
        spdlog::error("Failed to convert JSON to Property Tree: {}", e.what());
        return std::nullopt;
    }
}
