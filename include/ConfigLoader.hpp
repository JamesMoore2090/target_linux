#ifndef APP_CONFIG_HPP
#define APP_CONFIG_HPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

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

    bool isEnabled = true;
    std::string destination; // File output path
    
    // Output (CoT / TAK)
    std::string cot_ip = "239.2.3.1";
    int cot_port = 6969;
    std::string cot_protocol = "udp"; 

    // Asterix Output [NEW]
    
    std::string asterix_ip = "127.0.0.1";
    int asterix_port = 50010;

    // Toggles
    bool send_sensor_pos = false; // Send the Origin Point (Green Dot)
    bool send_tak_tracks = false; // [NEW] Send the actual Cat 48 Tracks
    bool send_asterix = false; // send ASterix

    // SSL Configuration [NEW]
    std::string ssl_client_cert;
    std::string ssl_client_pass;
    std::string ssl_trust_store;
    std::string ssl_trust_pass;

    // Processing
    std::vector<int> active_categories;

    // JSON Serialization
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AppConfig, 
        rx_port, cot_ip, cot_port, cot_protocol, 
        send_sensor_pos, send_tak_tracks, 
        send_asterix, asterix_ip, asterix_port,
        ssl_client_cert, ssl_client_pass, ssl_trust_store, ssl_trust_pass
    );
};
class ConfigLoader {
public:
    static bool load(const std::string& path, AppConfig& config);
};
#endif