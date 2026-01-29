#include "TargexCore.hpp"
#include <iostream>
#include <thread>
#include "Logger.hpp"
#include <filesystem>
#include <unistd.h>
#include <cstdlib>

namespace fs = std::filesystem;

TargexCore::TargexCore(const AppConfig& config): m_config(config) {
    Logger::debug("[CORE] Targex Recorder Created.");
}
TargexCore::~TargexCore() { stopCapture(); }
bool TargexCore::initialize() { return true; }

void TargexCore::startCapture() {
    if (m_isCapturing) return;
    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    std::string baseFilename = "output/" + m_config.site_name + "_raw.pcapng";
    std::string recCmd = "dumpcap -q -i " + m_config.interface + " -f \"" + filter + "\" "
                         "-w \"" + baseFilename + "\" -b duration:3600 > /dev/null 2>&1 &"; 
    
    Logger::info("[CORE] Starting Dumpcap...");
    if(system(recCmd.c_str()) == 0) m_isCapturing = true;
    else Logger::error("[CORE] Failed to start Dumpcap!");
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;
    m_isCapturing = false;
    system("pkill -9 dumpcap");
    Logger::info("[CORE] Recording Stopped.");
}