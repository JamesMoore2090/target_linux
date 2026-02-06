#include <QApplication>
#include "MainWindow.hpp"
#include "Logger.hpp"
#include "ConfigLoader.hpp"
#include "TargexCore.hpp"
#include "MarsEngine.hpp"
#include "WebServer.hpp"

int main(int argc, char* argv[]) {
    // 1. Initialize Qt Application
    QApplication app(argc, argv);
    app.setApplicationName("TARGEX");
    app.setApplicationVersion("1.0.0");

    AppConfig config;
    std::string configPath = "resources/config.json"; // Updated for deployment structure
    if (!ConfigLoader::load(configPath, config)) {
        Logger::error("Config file not found");
        return 0;
    }
    Logger::init("logs/targex_gui.log", config.log_level);

    // 3. Initialize Core Backend Systems (Non-Blocking)
    // These are passed by reference to MainWindow for GUI control
    TargexCore engine(config); 
    MarsEngine processor(config);
    WebServer webServer(config, processor);

    // 4. Launch the GUI
    // We pass the references so the buttons can call .start() and .stop()
    MainWindow w(config, engine, processor, webServer);
    w.show();

    // 5. Enter Qt Event Loop
    // This replaces the manual 'while(keepRunning)' loop from the CLI version
    return app.exec();
}