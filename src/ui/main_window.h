#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QMainWindow>

namespace Ui {
class main_window;
}

class main_window : public QMainWindow
{
    Q_OBJECT

public:
    explicit main_window(QWidget *parent = nullptr);
    ~main_window();

private slots:
    void on_register_btn_clicked();

    void on_verify_btn_clicked();

    void on_send_btn_clicked();

    void on_recv_btn_clicked();

private:
    Ui::main_window *ui;
};

#endif // MAIN_WINDOW_H
