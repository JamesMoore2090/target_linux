/* * TARGEX CLI Entry Point
 * Concepts: Argument Parsing, Signal Handling, Main Loop
 */

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include "TargexCore.hpp"
#include "Logger.hpp"
#include "ConfigLoader.hpp"
#include "WebServer.hpp"

// Atomic flag allows the signal handler to talk to the main loop safely
std::atomic<bool> keepRunning(true);

// specific signal handler function
void signalHandler(int signum) {
    std::cout << "\nInterrupt signal (" << signum << ") received. Shutting down TARGEX...\n";
    keepRunning = false;
}

int main(int argc, char* argv[]) {
    // 1. Register signal handlers (Ctrl+C)
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // 2. Parse CLI Arguments (Manual or using a library like CLI11)
    std::string configPath = "resources/config.json";
    if (argc > 1) {
        configPath = argv[1];
    }
    // Load Config
    AppConfig config;
    if (!ConfigLoader::load(configPath, config)) {
        // Fallback because Logger isn't ready yet
        std::cerr << "Failed to load config!" << std::endl;
        return 1;
    }
    // INITIALIZE LOGGER
    // Using values from your default.json
    Logger::init("logs/targex.log", config.log_level);

    

    // USAGE EXAMPLES
    Logger::info("TARGEX Server Starting...");
    Logger::info("Listening on Port: {}", config.rx_port); // {} is the placeholder for variables
    Logger::debug("Debug mode enabled. Verbose logging active.");

    Logger::info("Starting TARGEX CLI Server...");
    // std::cout << "[INFO] Loading configuration from: " << configPath << std::endl;

    // 3. Initialize Core System
    // RAII pattern: The 'engine' object is created here.
    TargexCore engine(config); 
    // 2. Start Web Server
    WebServer webServer(config, engine);
    webServer.start(); // Runs in background thread
    
    try {
        if (!engine.initialize()) {
            Logger::error("[ERROR] Initialization failed.");
            return 1;
        }
        engine.startCapture();
        // 4. Main Processing Loop
        // A headless server usually loops infinitely until told to stop
        while (keepRunning) {
            
            if (!engine.isCapturing()) {
                engine.startCapture(); 
            }

            // // B. Check Validity (using .is_null() from nlohmann library)
            // if (!packetJson.is_null()) {
                
            //     // C. Example Logic: Accessing Data
            //     // Tshark -T ek structure is usually: { "layers": { "ip": { ... }, "udp": { ... } } }
            //     webServer.broadcastPacket(packetJson.dump());
                
            //     if (packetJson.contains("layers")) {
            //         auto layers = packetJson["layers"];
                    
            //         // Log it just to prove it works
            //         // Logger::info("Packet received!"); 
            //         // std::cout << layers.dump() << std::endl; // Print raw JSON to console
            //     }
            // }
        }

    } catch (const std::exception& e) {
        Logger::error("Critical Exception: {}", e.what());
        return -1;
    }
    // 5. Cleanup
    // When loop breaks, 'engine' destructor is called automatically here.
    Logger::info("TARGEX Server stopped gracefully.");
    return 0;
}