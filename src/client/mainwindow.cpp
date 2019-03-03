#include <QMainWindow>
#include <QWidget>

#include "mainwindow.h"
#include "ui_mainwindow.h"

main_window::main_window(QWidget* parent) : QMainWindow(parent), ui(new Ui::main_window) {
    ui->setupUi(this);
}

main_window::~main_window() {
    delete ui;
}

void main_window::on_register_btn_clicked() {
    //Foobar
}

void main_window::on_verify_btn_clicked() {
    //Foobar
}

void main_window::on_send_btn_clicked() {
    //Foobar
}

void main_window::on_recv_btn_clicked() {
    //Foobar
}
