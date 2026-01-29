#pragma once
#include "httplib.h" // The new library
#include "ConfigLoader.hpp"
#include "TargexCore.hpp"
#include <string>
#include <thread>
#include <atomic>
#include "MarsEngine.hpp"

class WebServer {
public:
    WebServer(AppConfig& config, MarsEngine& engine);
    ~WebServer();

    void start();
    void stop();

private:
    AppConfig& m_config;
    MarsEngine& m_engine;
    
    // The Server Object
    httplib::Server m_server;
    std::thread m_serverThread;

    void setupRoutes();
};