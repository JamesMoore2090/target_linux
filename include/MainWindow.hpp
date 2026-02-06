#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>
#include "ConfigLoader.hpp"
#include "TargexCore.hpp"
#include "MarsEngine.hpp"
#include "WebServer.hpp"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    // Ensure this signature matches EXACTLY what is in the .cpp file
    MainWindow(AppConfig& config, TargexCore& engine, MarsEngine& processor, WebServer& server, QWidget *parent = nullptr);
    

private slots:
    void onStart();
    void onStop();
    void onOpenWeb();
    void appendLog(QString message);

private:
    AppConfig& m_config;
    TargexCore& m_engine;
    MarsEngine& m_processor;
    WebServer& m_webServer;

    QTextEdit* logView;
    QPushButton* startBtn;
    QPushButton* stopBtn;
    QPushButton* quitBtn;
};

#endif