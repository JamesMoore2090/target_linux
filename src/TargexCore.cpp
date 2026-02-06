#include "TargexCore.hpp"
#include "Logger.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#endif

namespace fs = std::filesystem;

TargexCore::TargexCore(AppConfig& config) : m_config(config) {
    Logger::debug("[CORE] Targex Recorder Created.");
}

TargexCore::~TargexCore() {
    stopCapture();
}

bool TargexCore::initialize() {
#ifdef _WIN32
    // Initialize Winsock for Windows networking
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        Logger::error("[CORE] WSAStartup failed: {}", result);
        return false;
    }
    Logger::info("[CORE] Winsock initialized.");
#endif
    return true;
}

void TargexCore::startCapture() {
    if (m_isCapturing) return;

    // 1. Cross-platform directory creation
    if (!fs::exists("output")) fs::create_directories("output");

    // 2. Generate Path-Safe Filename
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << "output/" << m_config.site_name << "_" 
        << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".pcap";
    std::string filename = oss.str();

    m_config.active_pcap_path = filename;

    // 3. Platform-specific Command Execution
    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    
#ifdef _WIN32
    // Windows: Use 'start /B' to run dumpcap in the background without a new window
    std::string recCmd = "start /B dumpcap -q -i " + m_config.interface + 
                         " -f \"" + filter + "\"" +
                         " -w \"" + filename + "\" > NUL 2>&1";
#else
    // Linux: Standard background process with PID tracking
    std::string recCmd = "dumpcap -q -i " + m_config.interface + 
                         " -f \"" + filter + "\"" +
                         " -w \"" + filename + "\" > /dev/null 2>&1 &";
#endif

    Logger::info("[CORE] Running CMD: {}", recCmd);
    Logger::info("[CORE] Starting Capture: {}", filename);
    if(system(recCmd.c_str()) == 0) {
        m_isCapturing = true;
    } else {
        Logger::error("[CORE] Failed to launch Dumpcap. Ensure Wireshark is in PATH.");
        m_config.active_pcap_path = "";
    }
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;

    terminateCaptureProcess();
    m_isCapturing = false;
    m_config.active_pcap_path = "";
    Logger::info("[CORE] Recording Stopped.");
}

void TargexCore::terminateCaptureProcess() {
#ifdef _WIN32
    // Windows equivalent to pkill
    system("taskkill /F /IM dumpcap.exe /T > NUL 2>&1");
#else
    // Linux termination
    system("pkill -9 dumpcap");
#endif
}

nlohmann::json TargexCore::pollData() {
    // Return empty batch for now; processing moved to MarsEngine
    return nlohmann::json::array();
}