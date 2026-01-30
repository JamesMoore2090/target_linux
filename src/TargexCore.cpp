#include "TargexCore.hpp"
#include <iostream>
#include <thread>
#include "Logger.hpp"
#include <filesystem>
#include <unistd.h>
#include <cstdlib>
#include <iomanip>
#include <ctime>
#include <sstream>

namespace fs = std::filesystem;

// [CHANGE] Constructor matches header (no const)
TargexCore::TargexCore(AppConfig& config): m_config(config) {
    Logger::debug("[CORE] Targex Recorder Created.");
}

TargexCore::~TargexCore() { stopCapture(); }
bool TargexCore::initialize() { return true; }

void TargexCore::startCapture() {
    if (m_isCapturing) return;

    // 1. Ensure Directory
    if (!fs::exists("output")) fs::create_directory("output");

    // 2. Generate Filename
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << "output/" << m_config.site_name << "_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".pcap";
    std::string filename = oss.str();

    // 3. [CRITICAL] Register as Active File
    m_config.active_pcap_path = filename;
    // 4. Start Dumpcap
    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    std::string recCmd = "dumpcap -q -i " + m_config.interface + 
                         " -f \"" + filter + "\"" +
                         " -w \"" + filename + "\"" +
                         " > /dev/null 2>&1 &"; 
    
    Logger::info("[CORE] Starting Capture: {}", filename);
    if(system(recCmd.c_str()) == 0) {
        m_isCapturing = true;
    } else {
        Logger::error("[CORE] Failed to start Dumpcap!");
        m_config.active_pcap_path = ""; // Reset on failure
    }
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;
    
    system("pkill -9 dumpcap");
    m_isCapturing = false;

    // 5. [CRITICAL] Clear Active File
    m_config.active_pcap_path = "";
    Logger::info("[CORE] Recording Stopped.");
}