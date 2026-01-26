#include "TargexCore.hpp"
#include <iostream>
#include <thread> // For sleep simulation
#include "Logger.hpp"
#include <filesystem> // C++17 standard for file checking
#include <unistd.h>   // For access() and X_OK
#include <cstdlib>    // For std::system
#include <cstdio>     // For popen (running shell commands)
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

// Constructor
TargexCore::TargexCore(const AppConfig& config): m_config(config), m_tsharkPipe(nullptr){
    Logger::debug("[CORE] Targex Engine Created.");

}

// Destructor
TargexCore::~TargexCore() {
    if (m_tsharkPipe) {
        Logger::info("Closing Tshark process...");
        pclose(m_tsharkPipe);
    }
    Logger::debug("[CORE] Targex Engine Destroyed. Cleaning up resources...");
}

// the idea behind this is to make sure everything is ready to go before we start recording data.
bool TargexCore::initialize() {
    Logger::debug("[CORE] Initializing");
    //check to see if tshark is installed
    std::string tsharkPath = "/usr/bin/tshark";

    if (!fs::exists(tsharkPath)){
        Logger::error("Dependency Missing: 'tshark' not found at {}.", tsharkPath);
        Logger::error("Please install it: sudo apt install tshark");
        return false;
    }
    Logger::info("Dependency Check: tshark found.");
    

    // check to see if dumpcap is executable

    const char* dumpcapPath = "/usr/bin/dumpcap";

    if (access(dumpcapPath, X_OK) != 0) {
        Logger::error("Permission Error: {} is not executable.", dumpcapPath);
        return false;
    }
    Logger::info("Permission Check: {} is executable.", dumpcapPath);

    // check to see if we have permission to run as non-sudo
    Logger::debug("Verifying non-sudo capture permissions...");
    
    // We run 'tshark -D' (List Interfaces) and redirect output to /dev/null
    // 2>&1 ensures we catch errors too.
    int result = std::system("tshark -D > /dev/null 2>&1");
    
    // In C++, system() returns the exit status. 0 usually means Success.
    if (result != 0) {
        Logger::error("Permission Error: 'tshark' cannot run as current user.");
        Logger::error("Hint: Try running 'sudo usermod -aG wireshark $USER' and rebooting.");
        return false;
    }
    Logger::info("Permission Check: User has rights to capture packets.");

    // check output directory

    // std::string outputDir = "output"; 

    try {
        if (!fs::exists(m_config.destination)) {
            Logger::warn("Output directory '{}' does not exist. Creating it...", m_config.destination);
            fs::create_directories(m_config.destination);
        } else {
            Logger::info("Output directory '{}' verified.", m_config.destination);
        }

        // Verify we can actually WRITE to this directory
        // We do this by creating a temp dummy file
        std::string testFile = m_config.destination + "/.perm_test";
        std::ofstream test(testFile);
        if (!test.is_open()) {
             Logger::error("Permission Error: Cannot write to output directory '{}'.", m_config.destination);
             return false;
        }
        test.close();
        fs::remove(testFile); // Clean up

    } catch (const fs::filesystem_error& e) {
        Logger::error("Filesystem Error: {}", e.what());
        return false;
    }
    
    Logger::debug("Initializtion complete!");


    return true; // Return false here to simulate a startup failure
}

void TargexCore::startCapture() {
    std::lock_guard<std::mutex> lock(m_pipeMutex);
    if (m_isCapturing) return;

    // 1. PREPARE VARIABLES
    // We don't need a timestamp here anymore! 
    // dumpcap adds "_00001_YYYYMMDD..." automatically when using ring buffers (-b).
    std::string baseFilename = "output/" + m_config.site_name + "_raw.pcapng";
    
    // Strict ASTERIX Filter
    std::string filter = "udp port " + std::to_string(m_config.rx_port);

    // 2. TASK A: THE RECORDER (Background Service)
    // -q: Quiet
    // -b duration:3600: Rotate every hour
    // -b files:24: Keep last 24 files (optional, prevents filling disk)
    // &: Runs in background so it doesn't block your C++ app
    std::string recCmd = "dumpcap -q -i " + m_config.interface + " -f \"" + filter + "\" "
                         "-w \"" + baseFilename + "\" "
                         "-b duration:3600 " 
                         "> /dev/null 2>&1 &"; // Silence output and background it

    Logger::info("Starting Background Recorder...");
    system(recCmd.c_str());

    // 3. TASK B: THE VIEWER (Live Feed)
    // We sniff the interface independently just for the JSON feed.
    // No writing to file (-w) here.
    std::string viewCmd = "tshark -l -n -i " + m_config.interface + " -f \"" + filter + "\" "
                          "-T ek -d udp.port==" + std::to_string(m_config.rx_port) + ",asterix";

    Logger::info("Starting Live Decoder...");
    
    // We open this one with popen so we can read the JSON
    m_tsharkPipe = popen(viewCmd.c_str(), "r");
    
    if (m_tsharkPipe) {
        m_isCapturing = true;
        m_currentFile = baseFilename; // Just for reference
    }
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;

    Logger::info("Stopping Capture (Force Kill)...");

    // 1. KILL FIRST (Resolve the deadlock)
    // We execute this immediately so Tshark dies.
    // The '-9' means "Force Kill" (cannot be ignored).
    int res1 = system("pkill -9 tshark");
    int res2 = system("pkill -9 dumpcap");

    std::lock_guard<std::mutex> lock(m_pipeMutex);

    // 2. CLOSE HANDLE SECOND
    // Now that Tshark is dead, pclose will return immediately.
    if (m_tsharkPipe) {
        pclose(m_tsharkPipe);
        m_tsharkPipe = nullptr;
    }

    // 3. Update State
    m_isCapturing = false;
    m_currentFile = "";
    
    // You should see this log now!
    Logger::info("Capture Stopped."); 
}

json TargexCore::pollData() {
    std::lock_guard<std::mutex> lock(m_pipeMutex);
    if (!m_isCapturing || !m_tsharkPipe) return nullptr;

    char buffer[65536]; // Keep the large buffer

    if (fgets(buffer, sizeof(buffer), m_tsharkPipe) != nullptr) {
        try {
            json rawPacket = json::parse(buffer);

            // The pipeline outputs strict EK JSON, so we just look for layers
            if (rawPacket.contains("layers")) {
                return rawPacket;
            }
            // Ignore metadata lines
            return nullptr;

        } catch (...) {
            return nullptr;
        }
    }
    return nullptr;
}

