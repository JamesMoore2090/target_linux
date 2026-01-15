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

        // 1. Get the list of files to process
        std::vector<std::string> files;
        for (const auto& item : x["files"]) {
            files.push_back(item.s());
        }
        
        std::string format = x["format"].s(); // "csv" or "json"

        // 2. Launch Background Thread (So the GUI doesn't freeze)
        std::thread([files, format, this]() {
            Logger::info("Job Started: Merging {} files...", files.size());
            
            // A. Construct the 'mergecap' command
            // mergecap -w public/temp_merged.pcapng output/file1.pcapng output/file2.pcapng ...
            std::string mergeCmd = "mergecap -w public/temp_merged.pcapng";
            
            // IMPORTANT: Use the 'output/' directory we verified earlier
            for(const auto& f : files) {
                mergeCmd += " \"output/" + f + "\"";
            }
            
            // Execute Merge
            int res1 = system(mergeCmd.c_str());
            if (res1 != 0) {
                Logger::error("Mergecap failed. Is it installed? (sudo apt install wireshark-common)");
                return;
            }

            // B. Convert to Requested Format
            std::string finalFile = "public/download." + format;
            std::string convertCmd;

            if (format == "json") {
                // Tshark -> JSON (EK format)
                convertCmd = "tshark -r public/temp_merged.pcapng -T ek > " + finalFile;
            } else {
                // Tshark -> CSV
                // We extract Time, Source, Destination, Protocol, Length, and Info
                convertCmd = "tshark -r public/temp_merged.pcapng -T fields -E separator=, -E header=y "
                             "-e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info "
                             "> " + finalFile;
            }

            // Execute Conversion
            int res2 = system(convertCmd.c_str());
            
            if (res2 == 0) {
                Logger::info("Job Complete: File ready at {}", finalFile);
            } else {
                Logger::error("Conversion failed.");
            }

        }).detach(); // Detach allows it to run independently

        return crow::response(202); // HTTP 202 Accepted
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