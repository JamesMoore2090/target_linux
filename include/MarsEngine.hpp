#ifndef MARS_ENGINE_HPP
#define MARS_ENGINE_HPP

#include "ConfigLoader.hpp"
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <nlohmann/json.hpp>

// OpenSSL Forward Declarations (Avoids pulling heavy headers here)
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

class MarsEngine {
public:
    MarsEngine(AppConfig& config);
    ~MarsEngine();

    void start();
    void stop();
    
    // API for WebServer to get visualization data
    std::vector<nlohmann::json> pollData();
    // Status Getter
    bool isTcpConnected() const { return m_tcpConnected; }

private:
    void processLoop();
    // Helper to route packets based on Protocol (UDP/TCP)
    void sendToTak(const std::string& xml);
    
    //  Manages TCP Reconnection logic
    void manageTcpConnection();

    // Helper to load .p12 files
    bool setupSSLContext();
    void cleanupSSL();

    AppConfig& m_config;
    std::atomic<bool> m_isRunning{false};
    std::thread m_workerThread;

    // Thread-safe buffer for the Web Interface
    std::deque<nlohmann::json> m_webQueue;
    std::mutex m_queueMutex;
    
    // State for CoT Generation
    double m_sensorLat = 0.0;
    double m_sensorLon = 0.0;
    bool m_hasOrigin = false;
    // --- NETWORKING STATE ---
    int m_udpSock = -1;
    int m_tcpSock = -1;
    bool m_tcpConnected = false;
    std::chrono::steady_clock::time_point m_lastTcpAttempt;

    // SSL State
    SSL_CTX* m_sslCtx = nullptr;
    SSL* m_ssl = nullptr;
    
    // To detect config changes
    std::string m_currentHost = "";
    int m_currentPort = 0;
};

#endif