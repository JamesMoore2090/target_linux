#pragma once
#include <crow.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include "ConfigLoader.hpp" // Assuming you moved struct AppConfig here or include ConfigLoader
#include "TargexCore.hpp"
#include "MarsEngine.hpp"

class WebServer {
public:
    WebServer(AppConfig& config, TargexCore& targexCore, MarsEngine& mars); // Reference so we can change settings
    ~WebServer();
    void start();
    void stop();

    // Function to broadcast real-time packets to the GUI
    void broadcastPacket(const std::string& jsonString);

private:
    AppConfig& m_config;
    crow::SimpleApp app;
    std::thread m_serverThread;
    TargexCore& m_engine;
    MarsEngine& m_mars;
    
    // Store active WebSocket connections so we know who to send data to
    std::vector<crow::websocket::connection*> m_connections;
    std::mutex m_connectionMutex; // Thread safety for the connection list

    void setupRoutes();
    // Helper for multipart parsing
    std::string getPartValue(const std::string& body, const std::string& boundary, const std::string& partName);
};