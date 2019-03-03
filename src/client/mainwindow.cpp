#include <QMainWindow>
#include <QWidget>

#include "logging.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

main_window::main_window(
        const char* dest, const char* port, client::database& db, QWidget* parent) :
        QMainWindow(parent),
        ui(new Ui::main_window), dev(dest, port, db) {
    ui->setupUi(this);
}

main_window::~main_window() {
    delete ui;
}

void main_window::on_register_btn_clicked() {
    const auto email = ui->register_email->text().toStdString();
    const auto password = ui->register_password->text().toStdString();
    spdlog::info("Register button clicked for {} {}", email, password);

    if (!dev.check_registration()) {
        dev.register_with_server(email, password);
    }
}

void main_window::on_verify_btn_clicked() {
    const auto email = ui->register_email->text().toStdString();
    const auto password = ui->register_password->text().toStdString();
    const auto code = ui->register_code->text().toStdString();

    spdlog::info("Verify button clicked {} {} {}", email, password, code);

    if (!dev.check_registration()) {
        dev.confirm_registration(email, std::stoull(code));
    }
}

void main_window::on_send_btn_clicked() {
    const auto dest = ui->send_dest->text().toStdString();
    const auto contents = ui->msg_contents->toPlainText().toStdString();

    spdlog::info("Mesg Send button clicked {} {}", dest, contents);

    crypto::secure_vector<std::byte> plain;
    for (const auto c : contents) {
        plain.push_back(std::byte{static_cast<unsigned char>(c)});
    }

    /*
     * There's an issue where simultaneous initial messages creates 2 seperate sessions
     * This prevents decryption on subsequent messages
     * Now, technically, I could mess around with ensuring sessions are consistent, but
     * currently it's easier to receive messages first, to ensure that cannot occur
     */

    const auto messages = dev.receive_signal_message();

    if (messages.has_value()) {
        spdlog::info("Received {} messages", messages->size());
        for (const auto& plain : *messages) {
            std::stringstream ss;
            for (const auto b : plain) {
                ss << static_cast<unsigned char>(std::to_integer<unsigned char>(b));
            }
            spdlog::info("Received plaintext {}", ss.str());
        }
    }

    dev.send_signal_message(plain, crypto::secure_vector<std::string>{dest});
}

void main_window::on_recv_btn_clicked() {
    spdlog::info("Mesg Recv button clicked");

    const auto messages = dev.receive_signal_message();

    if (messages.has_value()) {
        spdlog::info("Received {} messages", messages->size());
        for (const auto& plain : *messages) {
            std::stringstream ss;
            for (const auto b : plain) {
                ss << static_cast<unsigned char>(std::to_integer<unsigned char>(b));
            }
            spdlog::info("Received plaintext {}", ss.str());
        }
    }
}
