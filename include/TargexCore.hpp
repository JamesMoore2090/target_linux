#ifndef TARGEX_CORE_HPP
#define TARGEX_CORE_HPP

#include "ConfigLoader.hpp"
#include <string>
#include <atomic>
#include <mutex>
#include "json.hpp"
#include <filesystem>

class TargexCore {
public:
    TargexCore(AppConfig& config);
    ~TargexCore();

    bool initialize();   // [UPDATED] Now handles Winsock init
    void startCapture(); // [UPDATED] Cross-platform command execution
    void stopCapture();  // [UPDATED] Cross-platform process termination

    nlohmann::json pollData();

private:
    AppConfig& m_config;
    std::atomic<bool> m_isCapturing{false};
    
    // Helper to stop dumpcap specifically on Windows vs Linux
    void terminateCaptureProcess();
};

#endif