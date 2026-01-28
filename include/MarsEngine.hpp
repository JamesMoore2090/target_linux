#ifndef MARS_ENGINE_HPP
#define MARS_ENGINE_HPP

#include <string>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <atomic>
#include <mutex> // <--- ADDED

struct CoTConfig {
    std::string ip = "239.2.3.1";
    int port = 6969;
    std::string protocol = "udp"; // udp, tcp, ssl
    
    // SSL Certs
    std::string clientP12Path;
    std::string clientPwd;
    std::string trustP12Path;
    std::string trustPwd;
};

class MarsEngine {
public:
    using StatusCallback = std::function<void(std::string)>;

    MarsEngine();
    ~MarsEngine();

    void updateConfig(const CoTConfig& config);
    void processAndSend(const nlohmann::json& packet);
    
    // Thread-Safe Setter
    void setStatusCallback(StatusCallback cb) { 
        std::lock_guard<std::mutex> lock(m_statusMutex);
        m_statusCallback = cb; 
    }

    // Thread-Safe Getter (THE FIX)
    std::string getConnectionStatus() const { 
        std::lock_guard<std::mutex> lock(m_statusMutex);
        return m_connStatus; 
    }

private:
    struct GeoPoint { double lat; double lon; };

    void initSocket();
    bool initSSL();
    void cleanupSSL();
    void sendData(const std::string& data);
    std::string generateCoT(const nlohmann::json& ast);
    GeoPoint calculateLatLon(double rangeNM, double bearingDeg);
    
    // Thread-Safe Internal Setter
    void updateStatus(const std::string& status);

    int m_sockFd;
    CoTConfig m_config;
    
    // SSL Handles
    SSL_CTX* m_sslCtx;
    SSL* m_ssl;

    // Status State
    std::string m_connStatus;
    StatusCallback m_statusCallback;
    mutable std::mutex m_statusMutex; // <--- THE MUTEX
};

#endif