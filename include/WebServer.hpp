#pragma once
#include "ConfigLoader.hpp"
#include "MarsEngine.hpp"
#include "httplib.h" // Ensure this is the single-header version
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>

class WebServer {
public:
    WebServer(AppConfig& config, MarsEngine& engine);
    ~WebServer();

    void start();
    void stop();

private:
    void setupRoutes();

    AppConfig& m_config;
    MarsEngine& m_engine;

    // --- These were missing from your header ---
    std::atomic<bool> m_isRunning{false};
    std::thread m_serverThread;
    httplib::Server m_svr; 
};