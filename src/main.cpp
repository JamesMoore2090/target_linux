/* * TARGEX CLI Entry Point */

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <fstream> 
#include <nlohmann/json.hpp> 

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

    AppConfig config;

    // --- LAYER 1: LOAD DEFAULTS ---
    // (Optional: Load resources/config.json if needed, but we focus on the user file below)

    // --- LAYER 2: LOAD USER CONFIG (Nested Format) ---
    std::string configPath = "config.json";
    if (argc > 1) configPath = argv[1];

    std::ifstream f(configPath);
    if (f.good()) {
        try {
            nlohmann::json j;
            f >> j;

            // 1. SYSTEM
            if (j.contains("system")) {
                if(j["system"].contains("webport")) config.rx_port_web = j["system"]["webport"];
                if(j["system"].contains("site")) config.site_name = j["system"]["site"];
            }

            // 2. NETWORK INPUT
            if (j.contains("network_input")) {
                if(j["network_input"].contains("interface")) config.interface = j["network_input"]["interface"];
                if(j["network_input"].contains("port")) config.rx_port = j["network_input"]["port"];
            }

            // 3. TAK OUTPUT
            if (j.contains("TAKOutput")) {
                auto& tak = j["TAKOutput"];
                if(tak.contains("cot_ip")) config.cot_ip = tak["cot_ip"];
                if(tak.contains("cot_port")) config.cot_port = tak["cot_port"];
                if(tak.contains("cot_protocol")) config.cot_protocol = tak["cot_protocol"];
                
                if(tak.contains("send_sensor_pos")) config.send_sensor_pos = tak["send_sensor_pos"];
                if(tak.contains("send_tak_tracks")) config.send_tak_tracks = tak["send_tak_tracks"];
                
                // Note: The JSON has "send_asterix" inside TAKOutput, but we map it to our internal logic
                if(tak.contains("send_asterix")) config.send_asterix = tak["send_asterix"];

                // SSL
                if(tak.contains("ssl_client_cert")) config.ssl_client_cert = tak["ssl_client_cert"];
                if(tak.contains("ssl_client_pass")) config.ssl_client_pass = tak["ssl_client_pass"];
                if(tak.contains("ssl_trust_store")) config.ssl_trust_store = tak["ssl_trust_store"];
                if(tak.contains("ssl_trust_pass")) config.ssl_trust_pass = tak["ssl_trust_pass"];
            }

            // Fallback for correct spelling just in case
            else if (j.contains("AsterixOutput")) {
                if(j["AsterixOutput"].contains("asterix_ip")) config.asterix_ip = j["AsterixOutput"]["asterix_ip"];
                if(j["AsterixOutput"].contains("asterix_port")) config.asterix_port = j["AsterixOutput"]["asterix_port"];
            }

            Logger::info("Loaded complex configuration from {}", configPath);

        } catch(const std::exception& e) {
            Logger::error("Failed to parse config.json: {}", e.what());
        }
    } else {
        Logger::warn("Config file {} not found. Using internal defaults.", configPath);
    }

    // --- SAFETY CHECKS ---
    if (config.interface.empty()) {
        config.interface = "any";
        Logger::warn("Interface not defined. Defaulting to 'any'.");
    }

    // Logger Init
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << "logs/targex_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".log";
    Logger::init(oss.str(), config.log_level);

    Logger::info("TARGEX Server Starting...");
    Logger::info("Capture Interface: {}", config.interface);
    Logger::info("Listening on UDP Port: {}", config.rx_port);

    // Create Core Systems
    TargexCore engine(config); 
    MarsEngine processor(config);
    WebServer webServer(config, processor);
    
    try {
        if (!engine.initialize()) {
            Logger::error("[ERROR] Initialization failed.");
            return 1;
        }

        // Start Everything
        engine.startCapture();
        processor.start();
        webServer.start(); 

        Logger::info("System Ready. Web Interface available at http://localhost:{}", config.rx_port_web);
        
        if (config.send_tak_tracks || config.send_sensor_pos) {
            Logger::info("Persistence: Resuming output to TAK ({}:{})", config.cot_ip, config.cot_port);
        }

        while (keepRunning) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

    } catch (const std::exception& e) {
        Logger::error("Critical Exception: {}", e.what());
        return -1;
    }

    // Cleanup
    webServer.stop();
    processor.stop(); 
    engine.stopCapture();
    
    Logger::info("TARGEX Server stopped gracefully.");
    return 0;
}