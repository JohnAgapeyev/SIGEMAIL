#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QListWidgetItem>
#include <QMainWindow>
#include <QWidget>

#include "device.h"

namespace Ui {
    class main_window;
}

class main_window : public QMainWindow {
    Q_OBJECT

public:
    explicit main_window(
            const char* host, const char* port, client::database& db, QWidget* parent = nullptr);
    ~main_window();

private slots:
    void on_register_btn_clicked();

    void on_verify_btn_clicked();

    void on_send_btn_clicked();

    void on_recv_btn_clicked();

    void on_clear_messages_clicked();

    void on_message_list_itemDoubleClicked(QListWidgetItem* item);

private:
    Ui::main_window* ui;

    device dev;
};

#endif // MAIN_WINDOW_H
