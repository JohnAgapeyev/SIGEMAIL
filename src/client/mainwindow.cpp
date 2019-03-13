#include <QListWidgetItem>
#include <QMainWindow>
#include <QMessageBox>
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
    spdlog::debug("Register button clicked for {} {}", email, password);

    try {
        if (!dev.check_registration()) {
            dev.register_with_server(email, password);
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_verify_btn_clicked() {
    const auto email = ui->register_email->text().toStdString();
    const auto password = ui->register_password->text().toStdString();
    const auto code = ui->register_code->text().toStdString();

    spdlog::debug("Verify button clicked {} {} {}", email, password, code);

    try {
        if (!dev.check_registration()) {
            dev.confirm_registration(email, password, std::stoull(code));
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_send_btn_clicked() {
    const auto dest = ui->send_dest->text().toStdString();
    const auto contents = ui->msg_contents->toPlainText().toStdString();

    spdlog::debug("Mesg Send button clicked {} {}", dest, contents);

    crypto::secure_vector<std::byte> plain;

    try {
        for (const auto c : contents) {
            plain.push_back(std::byte{static_cast<unsigned char>(c)});
        }

        /*
         * There's an issue where simultaneous initial messages creates 2 seperate sessions
         * This prevents decryption on subsequent messages
         * Now, technically, I could mess around with ensuring sessions are consistent, but
         * currently it's easier to receive messages first, to ensure that cannot occur
         *
         * Fixing this would require message retry requests to discard the bad session on the sender side
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
                QMessageBox::information(this, tr("SIGEMAIL"), tr(ss.str().c_str()));
            }
        }

        dev.send_signal_message(plain, crypto::secure_vector<std::string>{dest});
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_recv_btn_clicked() {
    spdlog::debug("Mesg Recv button clicked");

    try {
        const auto messages = dev.receive_signal_message();

        if (messages.has_value()) {
            spdlog::info("Received {} messages", messages->size());
            for (const auto& plain : *messages) {
                std::stringstream ss;
                for (const auto b : plain) {
                    ss << static_cast<unsigned char>(std::to_integer<unsigned char>(b));
                }
                spdlog::info("Received plaintext {}", ss.str());
                QMessageBox::information(this, tr("SIGEMAIL"), tr(ss.str().c_str()));
            }
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_clear_messages_clicked() {
    spdlog::debug("Clear messages button clicked");
    ui->message_list->addItem("Foobar and stuff");
}

void main_window::on_message_list_itemDoubleClicked(QListWidgetItem* item) {
    spdlog::debug("Message doubled clicked {}", item->text().toStdString());
}
