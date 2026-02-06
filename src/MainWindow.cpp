#include "MainWindow.hpp"
#include "Logger.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDesktopServices>
#include <QUrl>
#include <QCoreApplication>
#include <QTimer> // Added for safety delay if needed

MainWindow::MainWindow(AppConfig& config, TargexCore& engine, MarsEngine& processor, WebServer& server, QWidget *parent)
    : QMainWindow(parent), m_config(config), m_engine(engine), m_processor(processor), m_webServer(server) 
{
    setWindowTitle("TARGEX Control Center");
    resize(800, 500);

    // Setup UI
    QWidget* central = new QWidget(this);
    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    logView = new QTextEdit(this);
    logView->setReadOnly(true);
    logView->setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas;");
    mainLayout->addWidget(logView);

    QHBoxLayout* btnLayout = new QHBoxLayout();
    startBtn = new QPushButton("Start Capture", this);
    stopBtn = new QPushButton("Stop Capture", this);
    QPushButton* webBtn = new QPushButton("Open Web UI", this);
    
    // Initially disable Stop button since we haven't started capturing yet
    // (This will be immediately flipped by onStart below)
    stopBtn->setEnabled(false);

    btnLayout->addWidget(startBtn);
    btnLayout->addWidget(stopBtn);
    btnLayout->addWidget(webBtn);
    mainLayout->addLayout(btnLayout);

    setCentralWidget(central);

    // --- LOGGING CONNECTION ---
    if (auto proxy = Logger::getQtProxy()) {
        connect(proxy, &QtLogSignalProxy::logReceived, this, &MainWindow::appendLog);
    }

    // --- BUTTON CONNECTIONS ---
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(stopBtn, &QPushButton::clicked, this, &MainWindow::onStop);
    connect(webBtn, &QPushButton::clicked, this, &MainWindow::onOpenWeb);

    Logger::info("GUI Initialized.");

    // Start Web Server immediately
    m_webServer.start();

    // [CHANGE] Start Recording Automatically
    // We use a single-shot timer with 0 delay to let the UI finish rendering first.
    // This prevents the UI from feeling "frozen" during the initial split-second of startup.
    QTimer::singleShot(100, this, &MainWindow::onStart);
}

void MainWindow::onStart() {
    Logger::info("[AUTO] Auto-starting capture sequence...");
    // m_engine.startCapture();
    m_processor.start();
    
    // Update UI state
    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);
}

void MainWindow::onStop() {
    // m_engine.stopCapture();
    m_processor.stop();
    
    // Update UI state
    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
}

void MainWindow::onOpenWeb() {
    Logger::info("Opening Web UI at http://127.0.0.1:{}", m_config.rx_port_web);
    QString url = QString("http://127.0.0.1:%1").arg(m_config.rx_port_web);
    QDesktopServices::openUrl(QUrl(url));
}

void MainWindow::appendLog(QString message) {
    logView->append(message);
}