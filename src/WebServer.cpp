#include "WebServer.hpp"
#include "Logger.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp> 

namespace fs = std::filesystem;

// --- HELPER: Read File Content ---
std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::stringstream buffer;
    buffer << f.rdbuf();
    return buffer.str();
}

WebServer::WebServer(AppConfig& config, TargexCore& targexCore) 
    : m_config(config), m_engine(targexCore) 
{
    setupRoutes();
}

WebServer::~WebServer() { 
    stop(); 
}

void WebServer::setupRoutes() {
    
    // 1. MOUNT STATIC ASSETS (js, css, images)
    // This handles /libs/..., /style.css, etc.
    if (!m_server.set_mount_point("/", "./public")) {
        Logger::error("Failed to mount ./public directory!");
    }
    // Also mount the "output" directory so users can download PCAP files
    m_server.set_mount_point("/output", "./output");

    // 2. PAGE ROUTES (Manual Mapping)
    // These fix the "Page not found" error for your menu buttons
    m_server.Get("/log", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(readFile("public/log.html"), "text/html");
    });

    m_server.Get("/files", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(readFile("public/files.html"), "text/html");
    });

    // 3. API: CONFIG (POST)
    m_server.Post("/api/config", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto x = nlohmann::json::parse(req.body);
            
            // Standard Net Config
            if(x.contains("rx_port")) m_config.rx_port = x["rx_port"].get<int>();
            if(x.contains("cot_ip")) m_config.cot_ip = x["cot_ip"].get<std::string>(); 
            if(x.contains("cot_port")) m_config.cot_port = x["cot_port"].get<int>(); 
            if(x.contains("cot_proto")) m_config.cot_protocol = x["cot_proto"].get<std::string>();
            if(x.contains("send_sensor_pos")) m_config.send_sensor_pos = x["send_sensor_pos"].get<bool>();

            // SSL Config [NEW]
            if(x.contains("ssl_client_pass")) m_config.ssl_client_pass = x["ssl_client_pass"].get<std::string>();
            if(x.contains("ssl_trust_pass")) m_config.ssl_trust_pass = x["ssl_trust_pass"].get<std::string>();
            
            // Note: For actual files, we currently store the filename/path string provided by the UI.
            // A full implementation would require a multipart upload handler to save the binary .p12 files.
            if(x.contains("ssl_client_cert")) m_config.ssl_client_cert = x["ssl_client_cert"].get<std::string>();
            if(x.contains("ssl_trust_store")) m_config.ssl_trust_store = x["ssl_trust_store"].get<std::string>();

            Logger::info("Config Updated: RX={} CoT={}:{} (SSL={})", 
                m_config.rx_port, m_config.cot_ip, m_config.cot_port, (m_config.cot_protocol=="ssl"));
            
            res.status = 200;
        } catch (...) { res.status = 400; }
    });

    // 4. API: DATA POLLING (GET)
    m_server.Get("/api/data", [&](const httplib::Request& req, httplib::Response& res) {
        
        nlohmann::json packetArray = nlohmann::json::array();
        
        // Loop to drain the buffer (up to 50 packets per HTTP request)
        for(int i=0; i<50; i++) {
            nlohmann::json packet = m_engine.pollData();
            if (packet.is_null()) break; // Stop if no more data
            packetArray.push_back(packet);
        }

        // Return Array (or empty array)
        if (!packetArray.empty()) {
            res.set_content(packetArray.dump(), "application/json");
        } else {
            res.set_content("[]", "application/json");
        }
    });

    // 5. API: FILE LIST (GET) - For File Manager
    m_server.Get("/api/files", [&](const httplib::Request& req, httplib::Response& res) {
        std::vector<nlohmann::json> fileList;
        std::string path = m_config.destination;
        
        // Find newest file to mark it as "Locked" (Active Recording)
        fs::path newestFile;
        auto newestTime = fs::file_time_type::min();
        if (fs::exists(path)) {
            for (const auto & entry : fs::directory_iterator(path)) {
                if(entry.path().extension() == ".pcapng") {
                    if(entry.last_write_time() > newestTime) {
                        newestTime = entry.last_write_time();
                        newestFile = entry.path();
                    }
                }
            }
        }

        int id = 0;
        if (fs::exists(path)) {
            for (const auto & entry : fs::directory_iterator(path)) {
                if(entry.path().extension() == ".pcapng") {
                    nlohmann::json f;
                    f["id"] = id++;
                    f["name"] = entry.path().filename().string();
                    f["size"] = entry.file_size();
                    
                    // Logic: If capturing, the newest file is locked
                    // Note: We need to expose isCapturing() in TargexCore to be 100% accurate,
                    // but checking if it matches the newest file is a good proxy.
                    bool isNewest = (entry.path() == newestFile);
                    f["locked"] = isNewest; 
                    
                    fileList.push_back(f);
                }
            }
        }
        
        nlohmann::json result;
        result["files"] = fileList;
        res.set_content(result.dump(), "application/json");
    });

    // 6. API: MERGE/CONVERT (POST) - For File Manager
    m_server.Post("/api/merge", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto x = nlohmann::json::parse(req.body);
            std::vector<std::string> files;
            for (const auto& item : x["files"]) files.push_back(item.get<std::string>());
            std::string format = x["format"].get<std::string>();

            // A. Merge
            std::string mergeCmd = "mergecap -w public/temp_merged.pcapng";
            for(const auto& f : files) mergeCmd += " \"output/" + f + "\"";
            if (system(mergeCmd.c_str()) != 0) { res.status = 500; return; }

            // B. Convert
            std::string finalFile = "public/download." + format;
            std::string convertCmd;
            if (format == "json") {
                convertCmd = "tshark -r public/temp_merged.pcapng -T ek > " + finalFile;
            } else {
                // Simplified CSV export for reliability
                convertCmd = "tshark -r public/temp_merged.pcapng -T fields -E separator=, -E header=y "
                             "-e ip.src -e ip.dst -e udp.dstport -e asterix "
                             "> " + finalFile;
            }
            if (system(convertCmd.c_str()) != 0) { res.status = 500; return; }

            // C. Reply
            nlohmann::json reply;
            reply["status"] = "ok";
            reply["url"] = "/download." + format;
            res.set_content(reply.dump(), "application/json");

        } catch (...) { res.status = 400; }
    });
}

void WebServer::start() {
    Logger::info("Web Server starting on Port {}...", m_config.rx_port_web);
    m_serverThread = std::thread([this]() {
        m_server.listen("0.0.0.0", m_config.rx_port_web);
    });
}

void WebServer::stop() {
    if (m_server.is_running()) m_server.stop();
    if (m_serverThread.joinable()) m_serverThread.join();
}