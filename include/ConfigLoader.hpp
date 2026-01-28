#ifndef APP_CONFIG_HPP
#define APP_CONFIG_HPP

#include <string>
#include <vector>

struct AppConfig {
    // System
    bool isMSCTactive = false;
    std::string site_name = "TARGEX_SITE";
    int tick_rate_ms = 10;
    std::string pid_file;
    int rx_port_web = 8080;
    std::string log_level = "info";

    // Input (Asterix)
    std::string interface;
    int rx_port = 8600;
    std::string multicast_group;

    // Output (CoT / TAK) -- [ADDED THESE TO FIX ERROR]
    bool isEnabled = true;
    std::string destination; // File output path
    
    std::string cot_ip = "239.2.3.1";
    int cot_port = 6969;
    std::string cot_protocol = "udp"; 

    // [NEW] Logic Flag
    bool send_sensor_pos = true;

    // SSL Configuration [NEW]
    std::string ssl_client_cert;
    std::string ssl_client_pass;
    std::string ssl_trust_store;
    std::string ssl_trust_pass;

    // Processing
    std::vector<int> active_categories;
};
class ConfigLoader {
public:
    static bool load(const std::string& path, AppConfig& config);
};
#endif