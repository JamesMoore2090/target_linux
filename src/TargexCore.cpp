#include "TargexCore.hpp"
#include <iostream>
#include <thread>
#include "Logger.hpp"
#include <filesystem>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h> // For UDP
#include <ctime>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

// --- TIME HELPER ---
std::string getIsoTime(int secondsOffset) {
    std::time_t now = std::time(nullptr) + secondsOffset;
    std::tm* t = std::gmtime(&now);
    std::stringstream ss;
    ss << std::put_time(t, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

TargexCore::TargexCore(const AppConfig& config): m_config(config), m_tsharkPipe(nullptr){
    Logger::debug("[CORE] Targex Engine Created.");
}

TargexCore::~TargexCore() { stopCapture(); }

bool TargexCore::initialize() { return true; } // (Keeping simple for brevity)

void TargexCore::startCapture() {
    std::lock_guard<std::mutex> lock(m_pipeMutex);
    if (m_isCapturing) return;

    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    
    // 1. Recorder
    std::string baseFilename = "output/" + m_config.site_name + "_raw.pcapng";
    std::string recCmd = "dumpcap -q -i " + m_config.interface + " -f \"" + filter + "\" "
                         "-w \"" + baseFilename + "\" -b duration:3600 > /dev/null 2>&1 &"; 
    system(recCmd.c_str());

    // 2. Decoder
    std::string viewCmd = "tshark -l -n -i " + m_config.interface + " -f \"" + filter + "\" "
                          "-T ek -d udp.port==" + std::to_string(m_config.rx_port) + ",asterix";

    Logger::info("Starting Live Decoder...");
    m_tsharkPipe = popen(viewCmd.c_str(), "r");
    
    if (m_tsharkPipe) {
        m_isCapturing = true;
        m_captureThread = std::thread(&TargexCore::captureLoop, this);
    }
}

void TargexCore::stopCapture() {
    if (!m_isCapturing) return;
    m_isCapturing = false;
    system("pkill -9 tshark");
    system("pkill -9 dumpcap");
    if (m_captureThread.joinable()) m_captureThread.join();
    
    std::lock_guard<std::mutex> lock(m_pipeMutex);
    if (m_tsharkPipe) { pclose(m_tsharkPipe); m_tsharkPipe = nullptr; }
    Logger::info("Capture Stopped."); 
}

void TargexCore::captureLoop() {
    char buffer[65536];
    auto lastCoTTime = std::chrono::steady_clock::now();
    double currentLat = 0.0;
    double currentLon = 0.0;
    bool hasOrigin = false;

    // UDP Socket for CoT
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    while (m_isCapturing && m_tsharkPipe) {
        if (fgets(buffer, sizeof(buffer), m_tsharkPipe) != nullptr) {
            try {
                nlohmann::json raw = nlohmann::json::parse(buffer);
                if (raw.contains("layers") && raw["layers"].contains("asterix")) {
                    auto ast = raw["layers"]["asterix"];
                    
                    // 1. SNIFF ORIGIN (Cat 34)
                    // We look for 034_120_LAT keys to auto-detect sensor location
                    for (auto& [key, val] : ast.items()) {
                        if (key.find("034_120_LAT") != std::string::npos) {
                            // Extract float
                            if(val.is_string()) currentLat = std::stod(val.get<std::string>());
                            else if(val.is_number()) currentLat = val.get<double>();
                        }
                        if (key.find("034_120_LON") != std::string::npos) {
                            if(val.is_string()) currentLon = std::stod(val.get<std::string>());
                            else if(val.is_number()) currentLon = val.get<double>();
                            hasOrigin = true; // We found a valid pair
                        }
                    }

                    // 2. BUFFER PACKET
                    {
                        std::lock_guard<std::mutex> lock(m_queueMutex);
                        m_packetQueue.push_back(raw);
                        if (m_packetQueue.size() > 1000) m_packetQueue.pop_front();
                    }
                }
            } catch (...) {}
        }

        // 3. SEND CoT HEARTBEAT (Every 10 Seconds)
        if (m_config.send_sensor_pos && hasOrigin) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastCoTTime).count() >= 10) {
                
                // Construct XML
                std::stringstream xml;
                xml << "<event version='2.0' uid='TARGEX-SENSOR-ORIGIN' type='a-f-G-U-C' "
                    << "time='" << getIsoTime(0) << "' start='" << getIsoTime(0) << "' stale='" << getIsoTime(20) << "'>"
                    << "<point lat='" << currentLat << "' lon='" << currentLon << "' hae='0' ce='10' le='10'/>"
                    << "<detail><contact callsign='ASTERIX_SENSOR'/><remarks>Auto-Detected Origin</remarks></detail>"
                    << "</event>";
                
                std::string msg = xml.str();

                // Send UDP
                struct sockaddr_in servaddr;
                memset(&servaddr, 0, sizeof(servaddr));
                servaddr.sin_family = AF_INET;
                servaddr.sin_port = htons(m_config.cot_port);
                inet_pton(AF_INET, m_config.cot_ip.c_str(), &servaddr.sin_addr);

                sendto(sockfd, msg.c_str(), msg.length(), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
                
                // Log strictly to debug to avoid spam
                Logger::debug("Sent Sensor Origin CoT to {}:{}", m_config.cot_ip, m_config.cot_port);
                
                lastCoTTime = now;
            }
        }
    }
    close(sockfd);
}

nlohmann::json TargexCore::pollData() {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    if (m_packetQueue.empty()) return nullptr;
    nlohmann::json packet = m_packetQueue.front();
    m_packetQueue.pop_front();
    return packet;
}