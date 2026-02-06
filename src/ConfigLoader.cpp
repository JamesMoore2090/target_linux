#include "ConfigLoader.hpp"
#include "json.hpp" 
#include <fstream>
#include <iostream>
#include <filesystem> // C++17 standard for cross-platform paths
#include "Logger.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

bool ConfigLoader::load(const std::string& path, AppConfig& config) {
    // 1. Resolve Absolute Path (Helps debug "File Not Found" on Windows)
    fs::path targetPath = fs::absolute(path);
    
    std::ifstream configFile(targetPath);
    if (!configFile.is_open()) {
        // Use fmt style logging supported by your Logger class
        Logger::error("[CONFIG] Error: Could not open config file at: {}", targetPath.string());
        return false;
    }

    try {
        json j;
        configFile >> j; // Parse the file

        // --- SYSTEM SETTINGS ---
        if (j.contains("system")) {
            config.isMSCTactive = j["system"].value("isMSCTActive", false);
            config.site_name = j["system"].value("site", "Unknown_Site");
            config.tick_rate_ms = j["system"].value("tick_rate_ms", 10);
            config.rx_port_web = j["system"].value("webport", 8080);


            // OS-Specific Default for PID File
            #ifdef _WIN32
                config.pid_file = j["system"].value("pid_file", "targex.pid"); // Local folder on Windows
            #else
                config.pid_file = j["system"].value("pid_file", "/tmp/targex.pid"); // /tmp on Linux
            #endif
        }

        // --- LOGGING ---
        if (j.contains("logging")) {
            config.log_level = j["logging"].value("level", "info");
        }

        // --- NETWORK INPUT ---
        if (j.contains("network_input")) {
            // OS-Specific Default for Interface
            #ifdef _WIN32
                // On Windows, we default to empty because we need a specific GUID.
                // If the JSON has a value, it uses that.
                config.interface = j["network_input"].value("interface", ""); 
            #else
                config.interface = j["network_input"].value("interface", "ens34");
            #endif

            config.rx_port = j["network_input"].value("port", 8600);
            config.multicast_group = j["network_input"].value("multicast_group", "0.0.0.0");
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

        Logger::info("[CONFIG] Configuration loaded successfully from: {}", targetPath.string());
        
        // Log the interface specifically so we know if it loaded correctly
        if (config.interface.empty()) {
            Logger::warn("[CONFIG] WARNING: Interface is empty! Capture may fail.");
        } else {
            Logger::info("[CONFIG] Active Interface: {}", config.interface);
        }

        return true;

    } catch (const json::parse_error& e) {
        Logger::error("[CONFIG] JSON Parse Error: {}", e.what());
        return false;
    }
}