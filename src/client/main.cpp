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
#include "logging.h"
#include "session.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

int main(int argc, char** argv) {
    // Check command line arguments.
    if (argc != 3) {
        std::cerr << "Usage: websocket-client-async-ssl <host> <port>\n"
                  << "Example:\n"
                  << "    websocket-client-async-ssl echo.websocket.org 443\n";
        return EXIT_FAILURE;
    }
    auto const host = argv[1];
    auto const port = argv[2];

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
    ctx.set_verify_callback(ssl::rfc2818_verification("localhost"));
#endif

    // Construct a signal set registered for process termination.
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);

    // Start an asynchronous wait for one of the signals to occur.
    signals.async_wait([](const boost::system::error_code& error, int signal_number) {
        //I'll use this if I need to have a global flag indicating whether to stop
        boost::ignore_unused(error, signal_number);
        spdlog::debug("Handler called");
    });

    std::shared_ptr<client_network_session> host_ref;
    try {
        host_ref = std::make_shared<client_network_session>(ioc, ctx, host, port);
    } catch (const boost::system::system_error& e) {
        spdlog::error("Client network session failed to establish: {}", e.what());
        return 1;
    }

    std::thread t{[&host_ref]() { host_ref->test_request(); }};

    // Run the I/O service. The call will return when
    // the socket is closed.
    ioc.run();

    t.join();

    spdlog::debug("Threads joined");

    return EXIT_SUCCESS;
}
