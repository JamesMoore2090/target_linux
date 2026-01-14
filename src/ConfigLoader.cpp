#include "ConfigLoader.hpp"
#include <nlohmann/json.hpp> // Now available automatically via CMake!
#include <fstream>
#include <iostream>
#include "Logger.hpp"

using json = nlohmann::json;

bool ConfigLoader::load(const std::string& path, AppConfig& config) {
    std::ifstream configFile(path);
    
    if (!configFile.is_open()) {
        Logger::error("[CONFIG] Error: Could not open config file: " + path );
        return false;
    }

    try {
        json j;
        configFile >> j; // Parse the file

        // Map JSON fields to our struct
        // We use .value() to provide a safe default if the field is missing
        if (j.contains("system")) {
            config.isMSCTactive = j["system"].value("isMSCTActive", false);
            config.site_name = j["system"].value("site", "");
            config.tick_rate_ms = j["system"].value("tick_rate_ms", 10);
            config.pid_file = j["system"].value("pid_file", "/tmp/targex.pid");
        }

        if (j.contains("logging")) {
            config.log_level = j["logging"].value("level", "info");
        }

        if (j.contains("network_input")) {
            config.interface = j["network_input"].value("interface", "");
            config.rx_port = j["network_input"].value("port", 8600);
            config.multicast_group = j["network_input"].value("multicast_group", "0.0.0.0");
        }

        if (j.contains("processing")) {
            config.active_categories = j["processing"].value("active_categories", std::vector<int>{});
        }
        if (j.contains("output")) {
            config.isEnabled = j["output"].value("enabled", true);
            config.destination = j["output"].value("destination", "");
        }

        Logger::info("[CONFIG] Configuration loaded successfully.");
        return true;

    } catch (const json::parse_error& e) {
        Logger::error("[CONFIG] JSON Parse Error: ", e.what());
        return false;
    }
}