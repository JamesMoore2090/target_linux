#pragma once
#include <crow.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include "ConfigLoader.hpp" // Assuming you moved struct AppConfig here or include ConfigLoader
#include "TargexCore.hpp"

class WebServer {
public:
    WebServer(AppConfig& config, TargexCore& targexCore); // Reference so we can change settings
    void start();
    void stop();

    // Function to broadcast real-time packets to the GUI
    void broadcastPacket(const std::string& jsonString);

private:
    AppConfig& m_config;
    crow::SimpleApp app;
    std::thread m_serverThread;
    TargexCore& m_engine;
    
    // Store active WebSocket connections so we know who to send data to
    std::vector<crow::websocket::connection*> m_connections;
    std::mutex m_connectionMutex; // Thread safety for the connection list

    void setupRoutes();
};