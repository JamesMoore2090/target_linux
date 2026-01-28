#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <functional> 

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>

// Configuration Struct
struct CoTConfig {
    std::string ip = "239.2.3.1";
    int port = 6969;
    std::string protocol = "udp"; // "udp", "tcp", "ssl"
    
    // SSL Specifics
    std::string clientP12Path;
    std::string clientPwd;
    std::string trustP12Path;
    std::string trustPwd;
};

class MarsEngine {
public:
    // Define the callback type
    using StatusCallback = std::function<void(std::string)>;

    MarsEngine();
    ~MarsEngine();

    // Configuration & Processing
    void updateConfig(const CoTConfig& config);
    void processAndSend(const nlohmann::json& packet);

    // Register the UI callback
    void setStatusCallback(StatusCallback cb) { m_statusCallback = cb; }
    
    // Status Getter
    std::string getConnectionStatus() const { return m_connStatus; }

private:
    CoTConfig m_config;
    int m_sockFd;
    StatusCallback m_statusCallback;
    
    // SSL Context
    SSL_CTX* m_sslCtx;
    SSL* m_ssl;
    
    std::string m_connStatus; 

    // Network Helpers
    void initSocket();
    bool initSSL();
    void cleanupSSL();
    void sendData(const std::string& data);
    void updateStatus(const std::string& status);

    // Data Helpers
    std::string generateCoT(const nlohmann::json& ast);
    
    
    // Math for Polar -> Lat/Lon conversion
    struct GeoPoint { double lat; double lon; };
    GeoPoint calculateLatLon(double range, double bearing);
};