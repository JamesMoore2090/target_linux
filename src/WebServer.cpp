#include "WebServer.hpp"
#include "Logger.hpp"
#include <filesystem>

namespace fs = std::filesystem;

// bridge class to send Crow logs to Targex Logger
// bridge class to send Crow logs to Targex Logger
class CrowToTargexLogger : public crow::ILogHandler {
public:
    // FIX: Changed 'std::string' to 'const std::string&' to match Crow's interface
    void log(const std::string& message, crow::LogLevel level) override {
        
        // Create a local copy if we need to modify it (stripping newline)
        std::string cleanMessage = message;
        if (!cleanMessage.empty() && cleanMessage.back() == '\n') {
            cleanMessage.pop_back();
        }

        // Map Crow levels to Targex Logger levels
        switch (level) {
            case crow::LogLevel::Debug:
                // Logger::debug("[WEB] {}", cleanMessage); 
                break;
            case crow::LogLevel::Info:
                Logger::info("[WEB] {}", cleanMessage);
                break;
            case crow::LogLevel::Warning:
                Logger::warn("[WEB] {}", cleanMessage);
                break;
            case crow::LogLevel::Error:
            case crow::LogLevel::Critical:
                Logger::error("[WEB] {}", cleanMessage);
                break;
        }
    }
};

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
        
        std::string format = x["format"].s(); // "csv" or "json"
        
        // --- 1. MERGE (Blocking) ---
        // We merged strict filtering here in previous steps, ensure headers are correct as per your last update
        std::string mergeCmd = "mergecap -w public/temp_merged.pcapng";
        for(const auto& f : files) mergeCmd += " \"output/" + f + "\"";
        
        if (system(mergeCmd.c_str()) != 0) {
            return crow::response(500, "Merge failed");
        }

        // --- 2. CONVERT (Blocking) ---
        std::string finalFile = "public/download." + format;
        std::string convertCmd;

        if (format == "json") {
             convertCmd = "tshark -r public/temp_merged.pcapng -T ek > " + finalFile;
        } else {
                // Tshark -> CSV (ALL FIELDS)
                
                // 1. Define the CSV Header (One massive string)
                std::string header = "echo \"SRC_IP,DST_IP,DST_PORT,"
                                     // --- CAT 34 HEADERS ---
                                     "C34_MsgType,C34_DataSourceID,C34_SectorNum,C34_TimeOfDay,C34_AntRotationSpeed,"
                                     "C34_Sys_NOGO,C34_Sys_RDPC,C34_Sys_RDPR,C34_Sys_OVL_RDP,C34_Sys_OVL_XMT,C34_Sys_MSC,C34_Sys_TSV,"
                                     "C34_PSR_ANT,C34_PSR_CHAB,C34_PSR_OVL,C34_PSR_MSC,"
                                     "C34_SSR_ANT,C34_SSR_CHAB,C34_SSR_OVL,C34_SSR_MSC,"
                                     "C34_MDS_ANT,C34_MDS_CHAB,C34_MDS_OVL_SUR,C34_MDS_MSC,C34_MDS_SCF,C34_MDS_DLF,C34_MDS_OVL_SCF,C34_MDS_OVL_DLF,"
                                     "C34_Proc_RED_RDP,C34_Proc_RED_XMT,"
                                     "C34_ProcPSR_POL,C34_ProcPSR_RED_RAD,C34_ProcPSR_STC,"
                                     "C34_ProcSSR_RED_RAD,C34_ProcMDS_RED_RAD,C34_ProcMDS_CLU,"
                                     "C34_MsgCnt_TYP,C34_MsgCnt_VAL,"
                                     "C34_Err_Range,C34_Err_Azimuth,"
                                     "C34_Win_RhoStart,C34_Win_RhoEnd,C34_Win_ThetaStart,C34_Win_ThetaEnd,"
                                     "C34_DataFilter,C34_Height,C34_Lat,C34_Lon,"
                                     // --- CAT 48 HEADERS ---
                                     "C48_DataSourceID,C48_TimeOfDay,C48_TrackNum,C48_AcftID,"
                                     "C48_Typ,C48_Sim,C48_RDP,C48_SPI,C48_RAB,C48_TST,C48_ERR,C48_XPP,C48_ME,C48_MI,C48_FOE,"
                                     "C48_Polar_Rho,C48_Polar_Theta,C48_Cart_X,C48_Cart_Y,"
                                     "C48_Mode2_V,C48_Mode2_G,C48_Mode2_L,C48_Mode2_Squawk,"
                                     "C48_Mode1_V,C48_Mode1_G,C48_Mode1_L,C48_Mode1_Code,"
                                     "C48_Mode2_Conf,"
                                     "C48_Mode3A_V,C48_Mode3A_G,C48_Mode3A_L,C48_Mode3A_Squawk,"
                                     "C48_Mode3A_Conf,"
                                     "C48_FL_V,C48_FL_G,C48_FlightLevel,"
                                     "C48_ModeC_V,C48_ModeC_G,C48_ModeC_Code,"
                                     "C48_Height3D,"
                                     "C48_RadDopp_D,C48_RadDopp_CAL,C48_RadDopp_DOP,C48_RadDopp_AMB,C48_RadDopp_FRQ,"
                                     "C48_Plot_SRL,C48_Plot_SRR,C48_Plot_SAM,C48_Plot_PRL,C48_Plot_PAM,C48_Plot_RPD,C48_Plot_APD,"
                                     "C48_TrkStat_CNF,C48_TrkStat_RAD,C48_TrkStat_DOU,C48_TrkStat_MAH,C48_TrkStat_CDM,C48_TrkStat_TRE,C48_TrkStat_GHO,C48_TrkStat_SUP,C48_TrkStat_TCC,"
                                     "C48_Calc_GS,C48_Calc_HDG,"
                                     "C48_Quality_X,C48_Quality_Y,C48_Quality_V,C48_Quality_H,"
                                     "C48_AcftAddr,"
                                     "C48_Com_COM,C48_Com_STAT,C48_Com_SI,C48_Com_MSSC,C48_Com_ARC,C48_Com_AIC,C48_Com_B1A,C48_Com_B1B"
                                     "\" > " + finalFile;

                system(header.c_str());

                // 2. Define the Tshark Command (Using underscore names from grep)
                convertCmd = "tshark -r public/temp_merged.pcapng -T fields -E separator=, -E header=n "
                             "-e ip.src -e ip.dst -e udp.dstport "
                             
                             // --- CAT 34 FIELDS ---
                             "-e asterix.034_000_MT "
                             "-e asterix.034_010 "
                             "-e asterix.034_020_SN "
                             "-e asterix.034_030 "
                             "-e asterix.034_041_ARS "
                             // 050 System Config
                             "-e asterix.034_050_01_NOGO -e asterix.034_050_01_RDPC -e asterix.034_050_01_RDPR -e asterix.034_050_01_OVL_RDP "
                             "-e asterix.034_050_01_OVL_XMT -e asterix.034_050_01_MSC -e asterix.034_050_01_TSV "
                             "-e asterix.034_050_02_ANT -e asterix.034_050_02_CHAB -e asterix.034_050_02_OVL -e asterix.034_050_02_MSC "
                             "-e asterix.034_050_03_ANT -e asterix.034_050_03_CHAB -e asterix.034_050_03_OVL -e asterix.034_050_03_MSC "
                             "-e asterix.034_050_04_ANT -e asterix.034_050_04_CHAB -e asterix.034_050_04_OVL_SUR -e asterix.034_050_04_MSC "
                             "-e asterix.034_050_04_SCF -e asterix.034_050_04_DLF -e asterix.034_050_04_OVL_SCF -e asterix.034_050_04_OVL_DLF "
                             // 060 Processing Mode
                             "-e asterix.034_060_01_RED_RDP -e asterix.034_060_01_RED_XMT "
                             "-e asterix.034_060_02_POL -e asterix.034_060_02_RED_RAD -e asterix.034_060_02_STC "
                             "-e asterix.034_060_03_RED_RAD -e asterix.034_060_04_RED_RAD -e asterix.034_060_04_CLU "
                             // Counts & Errors
                             "-e asterix.034_070_TYP -e asterix.034_070_COUNTER "
                             "-e asterix.034_090_RE -e asterix.034_090_AE "
                             "-e asterix.034_100_RHOS -e asterix.034_100_RHOE -e asterix.034_100_THETAS -e asterix.034_100_THETAE "
                             "-e asterix.034_110_TYP "
                             "-e asterix.034_120_H -e asterix.034_120_LAT -e asterix.034_120_LON "

                             // --- CAT 48 FIELDS ---
                             "-e asterix.048_010 "  // DataSource
                             "-e asterix.048_140 "  // Time
                             "-e asterix.048_161_TN " // Track Num
                             "-e asterix.048_240 "  // Acft ID
                             // 020 Target Report
                             "-e asterix.048_020_TYP -e asterix.048_020_SIM -e asterix.048_020_RDP -e asterix.048_020_SPI "
                             "-e asterix.048_020_RAB -e asterix.048_020_TST -e asterix.048_020_ERR -e asterix.048_020_XPP "
                             "-e asterix.048_020_ME -e asterix.048_020_MI -e asterix.048_020_FOE "
                             // Position
                             "-e asterix.048_040_RHO -e asterix.048_040_THETA "
                             "-e asterix.048_042_X -e asterix.048_042_Y "
                             // Mode 2
                             "-e asterix.048_050_V -e asterix.048_050_G -e asterix.048_050_L -e asterix.048_050_SQUAWK "
                             // Mode 1
                             "-e asterix.048_055_V -e asterix.048_055_G -e asterix.048_055_L -e asterix.048_055_CODE "
                             // Mode 2 Conf (Summarized to one hex field to save space)
                             "-e asterix.048_060 " 
                             // Mode 3A
                             "-e asterix.048_070_V -e asterix.048_070_G -e asterix.048_070_L -e asterix.048_070_SQUAWK "
                             // Mode 3A Conf (Summarized)
                             "-e asterix.048_080 "
                             // Flight Level
                             "-e asterix.048_090_V -e asterix.048_090_G -e asterix.048_090_FL "
                             // Mode C
                             "-e asterix.048_100_V -e asterix.048_100_G -e asterix.048_100 " // Extracting base for code
                             "-e asterix.048_110_3DHEIGHT "
                             // Radial Doppler (120)
                             "-e asterix.048_120_01_D -e asterix.048_120_01_CAL -e asterix.048_120_02_DOP -e asterix.048_120_02_AMB -e asterix.048_120_02_FRQ "
                             // Plot Characteristics (130)
                             "-e asterix.048_130_01_SRL -e asterix.048_130_02_SRR -e asterix.048_130_03_SAM -e asterix.048_130_04_PRL "
                             "-e asterix.048_130_05_PAM -e asterix.048_130_06_RPD -e asterix.048_130_07_APD "
                             // Track Status (170)
                             "-e asterix.048_170_CNF -e asterix.048_170_RAD -e asterix.048_170_DOU -e asterix.048_170_MAH -e asterix.048_170_CDM "
                             "-e asterix.048_170_TRE -e asterix.048_170_GHO -e asterix.048_170_SUP -e asterix.048_170_TCC "
                             // Calculated (200)
                             "-e asterix.048_200_GS -e asterix.048_200_HDG "
                             // Quality (210)
                             "-e asterix.048_210_X -e asterix.048_210_Y -e asterix.048_210_V -e asterix.048_210_H "
                             "-e asterix.048_220 " // Acft Addr
                             // Comms (230)
                             "-e asterix.048_230_COM -e asterix.048_230_STAT -e asterix.048_230_SI -e asterix.048_230_MSSC -e asterix.048_230_ARC "
                             "-e asterix.048_230_AIC -e asterix.048_230_B1A -e asterix.048_230_B1B "
                             
                             ">> " + finalFile;
        }
            if (system(convertCmd.c_str()) != 0) {
             return crow::response(500, "Conversion failed");
        }

        // --- 3. RESPOND ---
        // We return JSON telling the frontend the file is ready.
        crow::json::wvalue res;
        res["status"] = "ok";
        res["url"] = "/download." + format; 
        return crow::response(res);
    });
}



void WebServer::start() {
    Logger::info("Web Server starting on Port {}...", m_config.rx_port_web);

    // 1. SET CUSTOM LOGGER
    // We create a static instance so it lives for the lifetime of the app
    static CrowToTargexLogger customLogger;
    crow::logger::setHandler(&customLogger);

    // 2. SET LOG LEVEL
    // If you want to see the "Request: GET..." logs in your file, set this to INFO.
    // If you only want Warnings/Errors in the file, set to WARNING.
    app.loglevel(crow::LogLevel::Info); 

    // 3. RUN SERVER
    m_serverThread = std::thread([this](){
        app.port(m_config.rx_port_web).multithreaded().run();
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