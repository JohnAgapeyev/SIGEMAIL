#include <QApplication>
#include <QMainWindow>
#include <QWidget>
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
#include "mainwindow.h"
#include "session.h"
#include "ui_mainwindow.h"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

int main(int argc, char** argv) {
    // Check command line arguments.
    if (argc < 3) {
        std::cerr << "Usage: sigemail <host> <port> <optional client db name>\n";
        return EXIT_FAILURE;
    }

#if 1
    const auto host = argv[1];
    const auto port = argv[2];

    const auto db_name = (argc == 4) ? argv[3] : "client_db";

    spdlog::set_level(spdlog::level::debug);

    client::database client_db{db_name};

    QApplication app{argc, argv};
    try {
        main_window m{host, port, client_db};
        m.show();
        app.exec();
    } catch(const boost::system::system_error& e) {
        spdlog::error("Unable to initialize main window; {}", e.what());
        return EXIT_FAILURE;
    }
#else
    const auto email = argv[1];
    const auto password = argv[2];

    const auto contents = retrieve_emails(email, password);
    for (const auto& m : contents) {
        spdlog::error("Got message contents {}", m);
    }

#endif
    return EXIT_SUCCESS;
}
