#pragma once
#include <string>
#include <vector>

// Define a struct to hold our configuration
struct AppConfig {
    // System
    int tick_rate_ms = 10;
    std::string pid_file = "/var/run/targex.pid";
    std::string site_name = "";
    bool isMSCTactive = false;
    
    // Logging
    std::string log_level = "info";
    
    // Network
    int rx_port = 8600;
    std::string interface = "";
    std::string multicast_group = "239.0.0.1";

    
    // Processing
    std::vector<int> active_categories;

    // Output
    bool isEnabled = true; 
    std::string destination = "";
};

class ConfigLoader {
public:
    static bool load(const std::string& path, AppConfig& config);
};