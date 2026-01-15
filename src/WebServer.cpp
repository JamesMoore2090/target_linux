#include "WebServer.hpp"
#include "Logger.hpp"
#include <filesystem>

namespace fs = std::filesystem;

WebServer::WebServer(AppConfig& config, TargexCore& targexCore) : m_config(config),m_engine(targexCore) {
    setupRoutes();
}

WebServer::~WebServer() {
    stop(); // Safety net: Ensure we stop before destroying members
}

void WebServer::setupRoutes() {
    // ---------------------------------------------------------
    // 1. WEBSOCKET (MOVE THIS TO THE TOP!)
    // ---------------------------------------------------------
    CROW_WEBSOCKET_ROUTE(app, "/ws")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> _(m_connectionMutex);
            m_connections.push_back(&conn);
            Logger::info("GUI Connected! Total Clients: {}", m_connections.size());
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason, uint16_t code) {
            std::lock_guard<std::mutex> _(m_connectionMutex);
            m_connections.erase(
                std::remove(m_connections.begin(), m_connections.end(), &conn), 
                m_connections.end()
            );
            Logger::info("GUI Disconnected.");
        });

    // ---------------------------------------------------------
    // 2. STATIC FILES
    // ---------------------------------------------------------
    CROW_ROUTE(app, "/")([](){
        crow::response res;
        res.set_static_file_info("public/index.html");
        return res;
    });

    // This is the "greedy" route that was causing the problem
    CROW_ROUTE(app, "/<string>")
    ([](std::string path){
        // Safety check: Don't let it serve "ws" if the top route missed
        if (path == "ws") return crow::response(404);
        
        crow::response res;
        res.set_static_file_info("public/" + path);
        return res;
    });

    // ---------------------------------------------------------
    // 3. API ENDPOINTS
    // ---------------------------------------------------------
    CROW_ROUTE(app, "/api/settings")([this](){
        // ... (Keep existing code) ...
        crow::json::wvalue x;
        x["site_name"] = m_config.site_name;
        x["rx_port"] = m_config.rx_port;
        return x;
    });

    // API: STATUS (For Start/Stop)
    CROW_ROUTE(app, "/api/capture/status")([&](){
        crow::json::wvalue x;
        x["running"] = m_engine.isCapturing();
        return x;
    });

    // API: CONTROL (Start/Stop)
    CROW_ROUTE(app, "/api/capture/control").methods("POST"_method)
    ([&](const crow::request& req){
        auto x = crow::json::load(req.body);
        
        if (!x) {
            Logger::error("API Error: Failed to parse JSON body");
            return crow::response(400);
        }

        bool turnOn = x["action"].b();
        Logger::info("API Request Received: Set Capture to {}", turnOn ? "ON" : "OFF");

        if (turnOn) {
            m_engine.startCapture();
        } else {
            m_engine.stopCapture();
        }

        return crow::response(200);
    });

    // API: FILE LIST (THE ONLY ONE YOU NEED)
    CROW_ROUTE(app, "/api/files")([&](){
        std::vector<crow::json::wvalue> fileList;
        std::string path = m_config.destination;
        
        // Find newest file to lock it
        fs::path newestFile;
        auto newestTime = fs::file_time_type::min();

        // Pass 1: Find newest
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

        // Pass 2: Build JSON
        int id = 0;
        if (fs::exists(path)) {
            for (const auto & entry : fs::directory_iterator(path)) {
                if(entry.path().extension() == ".pcapng") {
                    crow::json::wvalue f;
                    f["id"] = id++;
                    f["name"] = entry.path().filename().string();
                    f["size"] = entry.file_size();
                    
                    // LOCK logic
                    bool isNewest = (entry.path() == newestFile);
                    f["locked"] = (m_engine.isCapturing() && isNewest);
                    
                    fileList.push_back(f);
                }
            }
        }
        crow::json::wvalue result;
        result["files"] = std::move(fileList);
        return result;
    });

    //  API: MERGE
    CROW_ROUTE(app, "/api/merge").methods("POST"_method)
    ([this](const crow::request& req){
        auto x = crow::json::load(req.body);
        if(!x) return crow::response(400);

        std::vector<std::string> files;
        for (const auto& item : x["files"]) files.push_back(item.s());
        
        std::string format = x["format"].s();
        
        // Background Job
        std::thread([files, format, this]() {
            Logger::info("Job Started: Merging {} files...", files.size());
            
            // 1. MERGE FILES
            std::string mergeCmd = "mergecap -w public/temp_merged.pcapng";
            for(const auto& f : files) mergeCmd += " \"output/" + f + "\"";
            
            if (system(mergeCmd.c_str()) != 0) {
                Logger::error("Merge failed.");
                return;
            }

            // 2. CONVERT
            std::string finalFile = "public/download." + format;
            std::string convertCmd;

            if (format == "json") {
                // Tshark -> JSON
                convertCmd = "tshark -r public/temp_merged.pcapng -T ek > " + finalFile;
            } else {
                // Tshark -> CSV (Custom Headers & Fields)
                
                // A. Define the Header Line (User Friendly Names)
                // Note: We use 'echo' to write the header first, because tshark -E header=y uses raw field names.
                std::string header = "echo \"SRC_IP,DST_IP,DST_PORT,"
                                     // CAT 34 Headers
                                     "Cat34_SAC,Cat34_SIC,Cat34_MsgType,Cat34_TimeOfDay,"
                                     "Cat34_PSR_ANT,Cat34_PSR_CHAB,Cat34_PSR_OVL,Cat34_PSR_MSC,"
                                     "Cat34_PSR_POL,Cat34_PSR_REDRAD,Cat34_PSR_STC,"
                                     "Cat34_Hgt,Cat34_Lat,Cat34_Lon,"
                                     // CAT 48 Headers
                                     "Cat48_SAC,Cat48_SIC,Cat48_TimeOfDay,Cat48_ReportType,Cat48_SIM,Cat48_RDP,"
                                     "Cat48_SPI,Cat48_RAB,Cat48_RHO,Cat48_THETA,Cat48_TrackNumber,Cat48_X,Cat48_Y,"
                                     "Cat48_GroundSpeed,Cat48_Heading,Cat48_Confirmed,Cat48_Radar,Cat48_DOU,"
                                     "Cat48_MAH,Cat48_CDM,Cat48_SigX,Cat48_SigY,Cat48_SigV,Cat48_SigH\" > " + finalFile;
                
                system(header.c_str());

                // B. Define the Tshark Command (Extract Raw Fields)
                // We append (>>) to the file we just created.
                convertCmd = "tshark -r public/temp_merged.pcapng -T fields -E separator=, -E header=n "
                             "-e ip.src -e ip.dst -e udp.dstport "
                             // CAT 34 Fields
                             "-e asterix.034_010_SAC -e asterix.034_010_SIC -e asterix.034_000_VALUE -e asterix.034_030_VALUE "
                             "-e asterix.034_050_PSR_ANT -e asterix.034_050_PSR_CHAB -e asterix.034_050_PSR_OVL -e asterix.034_050_PSR_MSC "
                             "-e asterix.034_060_PSR_POL -e asterix.034_060_PSR_REDRAD -e asterix.034_060_PSR_STC "
                             "-e asterix.034_120_HGT -e asterix.034_120_LAT -e asterix.034_120_LON "
                             // CAT 48 Fields
                             "-e asterix.048_010_SAC -e asterix.048_010_SIC -e asterix.048_140_VALUE -e asterix.048_020_TYP "
                             "-e asterix.048_020_SIM -e asterix.048_020_RDP -e asterix.048_020_SPI -e asterix.048_020_RAB "
                             "-e asterix.048_040_RHO -e asterix.048_040_THETA -e asterix.048_161_TRN -e asterix.048_042_X "
                             "-e asterix.048_042_Y -e asterix.048_200_GSP -e asterix.048_200_HDG -e asterix.048_170_CNF "
                             "-e asterix.048_170_RAD -e asterix.048_170_DOU -e asterix.048_170_MAH -e asterix.048_170_CDM "
                             "-e asterix.048_210_SIGX -e asterix.048_210_SIGY -e asterix.048_210_SIGV -e asterix.048_210_SIGH "
                             ">> " + finalFile;
            }

            if (system(convertCmd.c_str()) == 0) {
                Logger::info("Job Complete: File ready at {}", finalFile);
            } else {
                Logger::error("Conversion failed.");
            }

        }).detach();

        return crow::response(202);
    });
}


void WebServer::start() {
    // Run the server in a separate thread so it doesn't block Tshark
    m_serverThread = std::thread([this](){
        Logger::info("Web Server starting on Port 8080...");
        app.port(8080).multithreaded().run(); 
    });
}

void WebServer::broadcastPacket(const std::string& jsonString) {
    // LOCK THE THREAD
    std::lock_guard<std::mutex> _(m_connectionMutex);

    // 1. Log the "Guest List" size
    if (m_connections.empty()) {
        // Use static so we don't spam the log 100 times a second
        static int noClientCounter = 0;
        if (noClientCounter++ % 200 == 0) { // Log every ~2 seconds
            Logger::warn("Broadcast failed: Connection list is EMPTY. (Browser is connected but not registered?)");
        }
    } else {
        // Log that we are sending
        static int successCounter = 0;
        if (successCounter++ % 200 == 0) {
            Logger::info("Broadcasting packet to {} client(s). Data len: {}", m_connections.size(), jsonString.length());
        }
    }

    // 2. Send the data
    for (auto* conn : m_connections) {
        conn->send_text(jsonString);
    }
}

void WebServer::stop() {
    // 1. Tell Crow to stop accepting new connections
    // This breaks the app.run() loop inside the thread.
    app.stop(); 
    
    // 2. Wait for the thread to actually finish (Join)
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }
}