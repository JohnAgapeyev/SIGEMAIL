#include <algorithm>
#include <atomic>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "client_network.h"
#include "crypto.h"
#include "device.h"
#include "logging.h"
#include "session.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

int main(int argc, char** argv) {
    // Check command line arguments.
    if (argc != 5) {
        std::cerr << "Usage: websocket-client-async-ssl <host> <port>\n"
                  << "Example:\n"
                  << "    websocket-client-async-ssl echo.websocket.org 443\n";
        return EXIT_FAILURE;
    }
    const auto host = argv[1];
    const auto port = argv[2];

    spdlog::set_level(spdlog::level::debug);

    // The io_context is required for all I/O
    boost::asio::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tls};
    ctx.set_default_verify_paths();

    // Verify the remote server's certificate
#ifdef NO_SSL_VERIFY
    ctx.set_verify_mode(ssl::verify_none);
#else
    ctx.set_verify_mode(ssl::verify_peer);
    ctx.set_verify_callback(ssl::rfc2818_verification(host));
#endif

    client::database client_db{"client_db"};
    //device alice_dev{host, port, client_db};

    std::shared_ptr<client_network_session> host_ref;
    try {
        host_ref = std::make_shared<client_network_session>(ioc, ctx, host, port, client_db);
    } catch (const boost::system::system_error& e) {
        spdlog::error("Client network session failed to establish: {}", e.what());
        return EXIT_FAILURE;
    }

    if (!host_ref->request_verification_code(argv[3], argv[4])) {
        spdlog::error("Failed to request verification code from the server");
        return EXIT_FAILURE;
    }

    std::cout << "Enter the received registration code: ";

    uint64_t code;
    if (!(std::cin >> code)) {
        spdlog::error("Failed to convert user input to int code");
        return EXIT_FAILURE;
    }

    if (!host_ref->verify_verification_code(argv[3], code)) {
        spdlog::error("Failed to verify verification code to the server");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
