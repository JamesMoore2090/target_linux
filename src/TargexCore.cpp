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

void TargexCore::startCapture(){
    if (m_isCapturing) return;
    // 2. Construct Filename
    // Format: captures/14-01-2026_15-10_Radars_VA_01.pcapng
    std::string filename = m_config.destination + m_config.site_name + ".pcapng";
    
    Logger::info("Recording will be saved to: {}", filename);
    
    // 1. Construct the Command
    // -l : Line buffered (critical for real-time!)
    // -n : No name resolution (faster)
    // -T ek : Newline Delimited JSON output
    std::string cmd = "tshark -l -n -T ek -i ens34";
    
    // Append the write flags
    cmd += " -w \"" + filename + "\" -P";

    // -b duration:3600  -> Create a new file every 3600 seconds (1 Hour)
    cmd += " -b duration:3600";
    // cmd += " -b duration:60";
    // Append the port filter
    cmd += " -f \"udp port " + std::to_string(m_config.rx_port) + "\"";

    Logger::info("Launching Tshark: {}", cmd);

    // 2. Open the Pipe
    // "r" means we want to READ from this command
    m_tsharkPipe = popen(cmd.c_str(), "r");

    if (m_tsharkPipe) {
        m_isCapturing = true;
    }

    Logger::info("Tshark started successfully. Listening...");
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;

    Logger::info("Stopping Capture (Force Kill)...");

    // 1. KILL FIRST (Resolve the deadlock)
    // We execute this immediately so Tshark dies.
    // The '-9' means "Force Kill" (cannot be ignored).
    int res1 = system("pkill -9 tshark");
    int res2 = system("pkill -9 dumpcap");

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
    // 1. Check if pipe is valid
    if (!m_tsharkPipe) return nullptr;

    // 2. Read One Line from Tshark
    // fgets reads until it hits a Newline (\n)
    if (fgets(m_lineBuffer, sizeof(m_lineBuffer), m_tsharkPipe) != nullptr) {
        
        try {
            // 3. Parse that line into JSON
            // We verify it's not empty/garbage data
            std::string line(m_lineBuffer);
            if (line.length() < 5) return nullptr; // Skip empty lines

            json j = json::parse(line);
            
            // "ek" format often outputs an "index" line first, we ignore that.
            if (j.contains("index")) return nullptr;

            return j;

        } catch (const json::parse_error& e) {
            // Tshark might output status text "Capturing on 'ens34'..."
            // We ignore it, it's not JSON.
            // Logger::debug("Non-JSON line ignored: {}", m_lineBuffer);
            return nullptr;
        }
    }
    
    return nullptr;
}

