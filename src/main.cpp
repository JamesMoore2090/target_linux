/* * TARGEX CLI Entry Point */

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "TargexCore.hpp"
#include "Logger.hpp"
#include "ConfigLoader.hpp"
#include "WebServer.hpp"
#include "MarsEngine.hpp"

std::atomic<bool> keepRunning(true);

void signalHandler(int signum) {
    std::cout << "\nInterrupt signal (" << signum << ") received. Shutting down TARGEX...\n";
    keepRunning = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::string configPath = "resources/config.json";
    if (argc > 1) configPath = argv[1];

    AppConfig config;
    if (!ConfigLoader::load(configPath, config)) {
        std::cerr << "Failed to load config!" << std::endl;
        return 1;
    }

    // Logger Init
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << "logs/targex_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".log";
    Logger::init(oss.str(), config.log_level);

    Logger::info("TARGEX Server Starting...");
    Logger::info("Listening on Port: {}", config.rx_port);

    // 1. Create Core Systems
    TargexCore engine(config); 
    MarsEngine processor(config);
    WebServer webServer(config, processor);
    
    try {
        if (!engine.initialize()) {
            Logger::error("[ERROR] Initialization failed.");
            return 1;
        }

        // 2. Start Everything
        engine.startCapture();
        processor.start();
        webServer.start(); 

        Logger::info("System Ready. Web Interface available at http://localhost:{}", config.rx_port_web);

        // 3. Main Loop (IDLE)
        // We do NOT call pollData() here. We just wait for Ctrl+C.
        // The WebServer thread will handle all data consumption via /api/data
        while (keepRunning) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

    } catch (const std::exception& e) {
        Logger::error("Critical Exception: {}", e.what());
        return -1;
    }

    // 4. Cleanup
    webServer.stop();
    engine.stopCapture();
    Logger::info("TARGEX Server stopped gracefully.");
    return 0;
}