#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <QListWidgetItem>
#include <QInputDialog>
#include <QMainWindow>
#include <QMessageBox>
#include <QWidget>

#include "client_network.h"
#include "error.h"
#include "logging.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

static const std::string start_sigemail = "--BEGIN SIGEMAIL ENCRYPTED EXPORT MESSAGE--\r\n";
static const std::string end_sigemail = "--END SIGEMAIL ENCRYPTED EXPORT MESSAGE--\r\n";

main_window::main_window(
        const char* dest, const char* port, client::database& db, QWidget* parent) :
        QMainWindow(parent),
        ui(new Ui::main_window), client_db(db), dev(dest, port, client_db) {
    ui->setupUi(this);
}

main_window::~main_window() {
    delete ui;
}

void main_window::send_message(const std::string& dest, const std::string& contents) {
    crypto::secure_vector<std::byte> plain;

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
    recv_messages();

    dev.send_signal_message(plain, crypto::secure_vector<std::string>{dest});
}

std::vector<std::string> main_window::recv_messages() {
    const auto messages = dev.receive_signal_message();

    std::vector<std::string> plaintexts;

    if (messages.has_value()) {
        spdlog::info("Received {} messages", messages->size());
        for (const auto& plain : *messages) {
            std::stringstream ss;
            for (const auto b : plain) {
                ss << static_cast<unsigned char>(std::to_integer<unsigned char>(b));
            }
            std::string plaintext = ss.str();
            spdlog::info("Received plaintext {}", plaintext);
            QMessageBox::information(this, tr("SIGEMAIL"), tr(plaintext.c_str()));

            plaintexts.emplace_back(std::move(plaintext));
        }
    }
    return plaintexts;
}

void main_window::on_register_btn_clicked() {
    const auto email = ui->register_email->text().toStdString();
    const auto password = ui->register_password->text().toStdString();
    spdlog::debug("Register button clicked for {} {}", email, password);

    if (email.empty() || password.empty()) {
        QMessageBox::information(this, tr("Something went wrong!"), tr("Please enter both your email address and password before attempting to register with SIGEMAIL"));
        return;
    }

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

    if (email.empty() || password.empty()) {
        QMessageBox::information(this, tr("Something went wrong!"), tr("Please reenter both your email address and password before attempting to confirm your registration with SIGEMAIL"));
        return;
    }
    if (code.empty()) {
        QMessageBox::information(this, tr("Something went wrong!"), tr("Please enter your received registration code before verifying your registration with SIGEMAIL"));
        return;
    }

    try {
        if (!dev.check_registration()) {
            dev.confirm_registration(email, password, std::stoull(code));
        } else {
            QMessageBox::information(this, tr("Something went wrong!"), tr("You're already registered with SIGEMAIL!"));
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_send_btn_clicked() {
    const auto dest = ui->send_dest->text().toStdString();
    const auto contents = ui->msg_contents->toPlainText().toStdString();

    spdlog::debug("Mesg Send button clicked {} {}", dest, contents);

    if (!dev.check_registration()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Please Register with SIGEMAIL before attempting to send your emails"));
        return;
    }

    if (dest.empty() || contents.empty()) {
        QMessageBox::information(this, tr("Something went wrong!"), tr("Your destination email and/or your message cannot be empty"));
        return;
    }

    if (!dev.contact_exists(dest)) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Destination email is not currently registered with SIGEMAIL"));
        return;
    }

    try {
        send_message(dest, contents);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_recv_btn_clicked() {
    spdlog::debug("Mesg Recv button clicked");
    if (!dev.check_registration()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Please Register with SIGEMAIL before attempting to receive your emails"));
        return;
    }

    try {
        recv_messages();
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
}

void main_window::on_clear_messages_clicked() {
    spdlog::debug("Clear messages button clicked");
    ui->message_list->clear();
}

void main_window::on_message_list_itemDoubleClicked(QListWidgetItem* item) {
    const auto message_text = item->text().toStdString();
    spdlog::debug("Message doubled clicked {}", message_text);

    std::stringstream ss{message_text};
    int message_id;
    ss >> message_id;

    try {
        const auto contents = client_db.get_message_contents(message_id);
        const auto start_index = contents.find(start_sigemail);
        if (start_index == std::string::npos) {
            //Message does not contain the start banner
            QMessageBox::information(this, tr("SIGEMAIL"), tr(contents.c_str()));
            return;
        }
        const auto end_index = contents.find(end_sigemail);
        if (end_index < start_index) {
            //Invalid message
            QMessageBox::information(this, tr("SIGEMAIL"), tr(contents.c_str()));
            return;
        }
        const auto ciphertext_str = contents.substr(start_index + start_sigemail.size(), end_index - start_sigemail.size());
        std::stringstream ss{ciphertext_str};
        crypto::secure_vector<std::byte> raw_ciphertext;
        {
            boost::archive::text_iarchive arch{ss};
            arch >> raw_ciphertext;
        }

        crypto::secure_string crypto_password{QInputDialog::getText(this, tr("Title"), tr("Enter the password to decrypt the exported message")).toStdString()};
        if (crypto_password.empty()) {
            QMessageBox::information(this, tr("SIGEMAIL"),
                    tr("You have canceled message retrieval due to not providing a password for decryption"));
            return;
        }
        const auto raw_plaintext = crypto::decrypt_password(raw_ciphertext, crypto_password);
        crypto::secure_string plaintext;
        for (const auto b : raw_plaintext) {
            plaintext.push_back(std::to_integer<uint8_t>(b));
        }
        QMessageBox::information(this, tr("SIGEMAIL"), tr(plaintext.c_str()));
    } catch(const db_error& e) {
        spdlog::error("Message contents retrieval failed {}", e.what());
        QMessageBox::information(this, tr("SIGEMAIL"), tr("Unable to retrieve message contents from the database"));
    } catch(const crypto::expected_error& e) {
        spdlog::error("Message retrieval failed to decrypt");
        QMessageBox::information(this, tr("SIGEMAIL"), tr("Invalid password to decrypt encrypted export message"));
    }
}

void main_window::on_fetch_email_clicked() {
    spdlog::debug("Fetch emails button clicked");
    if (!dev.check_registration()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Please Register with SIGEMAIL before attempting to fetch your emails"));
        return;
    }

    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey]
            = client_db.get_self_data();

    const auto email_contents = retrieve_emails(self_email.c_str(), email_pass.c_str());

    try {
        for (const auto& m : email_contents) {
            client_db.add_message(m);
        }
    } catch (const db_error& e) {
        spdlog::error("Email insertion db error {}", e.what());
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Something went wrong when saving your imported email messages!"));
    }

    //Update the message list based on the database
    ui->message_list->clear();
    for (const auto& [message_id, contents, timestamp] : client_db.get_messages()) {
        std::stringstream ss;
        ss << message_id << ' ' << timestamp;
        ui->message_list->addItem(ss.str().c_str());
    }
}

void main_window::on_send_export_clicked() {
    const auto dest = ui->send_dest->text().toStdString();
    const auto contents = ui->msg_contents->toPlainText().toStdString();

    spdlog::debug("Mesg Send Export button clicked {} {}", dest, contents);

    if (!dev.check_registration()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Please Register with SIGEMAIL before attempting to send your emails"));
        return;
    }

    if (!dev.contact_exists(dest)) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Destination email is not currently registered with SIGEMAIL"));
        return;
    }

    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey]
            = client_db.get_self_data();

    try {
        send_message(dest, contents);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Something went wrong!"), tr(e.what()));
    }
    crypto::secure_string crypto_password;
retry_prompt:
    crypto_password = QInputDialog::getText(this, tr("Title"), tr("Enter the password to encrypt the exported message")).toStdString();
    if (crypto_password.empty()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("You must enter a password for exporting emails"));
        goto retry_prompt;
    }

    //Wrap the message with the banner designating an encrypted export message
    crypto::secure_vector<std::byte> raw_message;
    for (const auto c : contents) {
        raw_message.emplace_back(std::byte{static_cast<unsigned char>(c)});
    }

    std::stringstream ss;
    const auto ciphertext = crypto::encrypt_password(raw_message, crypto_password);
    {
        boost::archive::text_oarchive arch{ss};
        arch << ciphertext;
    }

    auto serialized_ciphertext = ss.str();
    serialized_ciphertext.insert(serialized_ciphertext.begin(), start_sigemail.begin(), start_sigemail.end());
    serialized_ciphertext.append(end_sigemail);

    export_email(self_email.c_str(), email_pass.c_str(), serialized_ciphertext.c_str());
}

void main_window::on_recv_export_clicked() {
    if (!dev.check_registration()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("Please Register with SIGEMAIL before attempting to receive your emails"));
        return;
    }
    const auto [self_email, self_device_id, auth_token, email_pass, self_identity, self_prekey]
            = client_db.get_self_data();

    const auto exported = recv_messages();

    crypto::secure_string crypto_password;
retry_prompt:
    crypto_password = QInputDialog::getText(this, tr("Title"), tr("Enter the password to encrypt the exported message")).toStdString();
    if (crypto_password.empty()) {
        QMessageBox::information(this, tr("SIGEMAIL"),
                tr("You must enter a password for exporting emails"));
        goto retry_prompt;
    }

    for (const auto& plain : exported) {
        //Wrap the message with the banner designating an encrypted export message
        crypto::secure_vector<std::byte> raw_message;
        for (const auto c : plain) {
            raw_message.emplace_back(std::byte{static_cast<unsigned char>(c)});
        }

        std::stringstream ss;
        const auto ciphertext = crypto::encrypt_password(raw_message, crypto_password);
        {
            boost::archive::text_oarchive arch{ss};
            arch << ciphertext;
        }

        auto serialized_ciphertext = ss.str();
        serialized_ciphertext.insert(serialized_ciphertext.begin(), start_sigemail.begin(), start_sigemail.end());
        serialized_ciphertext.append(end_sigemail);

        export_email(self_email.c_str(), email_pass.c_str(), serialized_ciphertext.c_str());
    }
}
