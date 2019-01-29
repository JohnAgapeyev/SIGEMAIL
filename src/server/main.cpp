#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "crypto.h"
#include "listener.h"
#include "logging.h"
#include "server_network.h"
#include "server_state.h"
#include "session.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

int main(int argc, char* argv[]) {
    // Check command line arguments.
    if (argc != 3) {
        std::cerr << "Usage: websocket-server-async-ssl <port> <threads>\n"
                  << "Example:\n"
                  << "    websocket-server-async-ssl 8080 1\n";
        return EXIT_FAILURE;
    }
    const auto port = static_cast<unsigned short>(std::atoi(argv[1]));
    const auto threads = std::max<int>(1, std::atoi(argv[2]));

    // The io_context is required for all I/O
    boost::asio::io_context ioc{threads};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tls};

    // This holds the self-signed certificate used by the server
    load_server_certificate(ctx);

    spdlog::set_level(spdlog::level::trace);

    db::database server_db{"server_db"};
    // Create and launch a listening port
    std::make_shared<listener>(ioc, ctx, tcp::endpoint{tcp::v4(), port}, server_db)->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i) {
        v.emplace_back([&ioc] { ioc.run(); });
    }
    ioc.run();

    return EXIT_SUCCESS;
}
