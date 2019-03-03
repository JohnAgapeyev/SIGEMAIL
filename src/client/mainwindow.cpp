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
}

void main_window::on_verify_btn_clicked() {
    const auto email = ui->register_email->text().toStdString();
    const auto password = ui->register_password->text().toStdString();
    const auto code = ui->register_code->text().toStdString();

    spdlog::info("Verify button clicked {} {} {}", email, password, code);
}

void main_window::on_send_btn_clicked() {
    const auto dest = ui->send_dest->text().toStdString();
    const auto contents = ui->msg_contents->toPlainText().toStdString();

    spdlog::info("Mesg Send button clicked {} {}", dest, contents);
}

void main_window::on_recv_btn_clicked() {
    spdlog::info("Mesg Recv button clicked");
}
