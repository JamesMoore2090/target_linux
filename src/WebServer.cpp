#include "WebServer.hpp"
#include "Logger.hpp"
#include <fstream>
#include <sstream>
#include <dirent.h> 
#include <sys/stat.h> 
#include <cstdio> 
#include <vector>
#include <algorithm>

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "<h1>404 Not Found: " + path + "</h1>";
    std::stringstream buf; buf << f.rdbuf();
    return buf.str();
}

WebServer::WebServer(AppConfig& config, MarsEngine& engine) 
    : m_config(config), m_engine(engine) 
{
    // Ensure output directory exists
    struct stat st = {0};
    if (stat("./output", &st) == -1) {
        #ifdef _WIN32
            _mkdir("./output");
        #else
            mkdir("./output", 0777);
        #endif
    }
    setupRoutes();
}

WebServer::~WebServer() {
    stop();
}

void WebServer::start() {
    m_serverThread = std::thread([this]() {
        Logger::info("Web Server starting on port {}", m_config.rx_port_web);
        m_server.listen("0.0.0.0", m_config.rx_port_web);
    });
}

void WebServer::stop() {
    m_server.stop();
    if (m_serverThread.joinable()) m_serverThread.join();
}

void WebServer::setupRoutes() {
    // 1. STATIC
    m_server.set_mount_point("/", "./public");

    // 2. LOGS
    m_server.Get("/api/logs", [&](const httplib::Request& req, httplib::Response& res) {
        std::ifstream f("targex.log");
        std::stringstream buffer;
        buffer << f.rdbuf();
        res.set_content(buffer.str(), "text/plain");
    });
    m_server.Get("/asterixLiveLog", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(readFile("./public/asterixLiveLog.html"), "text/html");
    });

    // Maps the browser URL "/files" to the file "pcapFilesAndMerge.html"
    m_server.Get("/pcapFilesAndMerge", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(readFile("./public/pcapFilesAndMerge.html"), "text/html");
    });

    //--- API: LIVE LOGS ---
    m_server.Get("/api/logs", [&](const httplib::Request&, httplib::Response& res) {
        std::ifstream f(m_config.active_log_path);
        if(f) {
            std::stringstream buffer;
            buffer << f.rdbuf();
            res.set_content(buffer.str(), "text/plain");
        } else {
            res.set_content("Log file not found: " + m_config.active_log_path, "text/plain");
        }
    });

    // --- API: LIST FILES ---
    m_server.Get("/api/files", [&](const httplib::Request&, httplib::Response& res) {
        nlohmann::json root;
        nlohmann::json filesArr = nlohmann::json::array();
        
        std::string dirPath = "./output";
        DIR *dir; struct dirent *ent;
        
        if ((dir = opendir (dirPath.c_str())) != NULL) {
            while ((ent = readdir (dir)) != NULL) {
                std::string name = ent->d_name;
                if(name == "." || name == "..") continue;
                
                // Construct relative path "output/filename.pcap" to match config
                std::string relativePath = "output/" + name; 
                std::string fullSystemPath = dirPath + "/" + name;

                struct stat st;
                stat(fullSystemPath.c_str(), &st);
                
                nlohmann::json item;
                item["name"] = name;
                item["size"] = st.st_size;

                // [CRITICAL] Check if this is the active file
                if (!m_config.active_pcap_path.empty() && m_config.active_pcap_path == relativePath) {
                    item["locked"] = true;
                } else {
                    item["locked"] = false;
                }
                
                filesArr.push_back(item);
            }
            closedir (dir);
        }
        
        root["files"] = filesArr; 
        res.set_content(root.dump(), "application/json");
    });

    // --- API: MERGE & CONVERT FILES ---
    m_server.Post("/api/merge", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::vector<std::string> files = json["files"];
            std::string format = json["format"]; // "csv" or "json"

            if (files.empty()) { res.status = 400; return; }

            // --- STEP 1: PREPARE FILENAMES ---
            auto t = std::time(nullptr);
            auto tm = *std::localtime(&t);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
            std::string timestamp = oss.str();
            
            // The file we will eventually convert. 
            // We use this variable so we don't care if it came from a merge or a single file.
            std::string sourcePcap = "";
            bool createdTempPcap = false;

            // --- STEP 2: MERGE (If needed) ---
            if (files.size() > 1) {
                // Save to output/ directory
                std::string mergedPath = "output/temp_merge_" + timestamp + ".pcap";
                
                std::string cmd = "mergecap -w " + mergedPath;
                for(const auto& f : files) {
                    if(f.find("..") != std::string::npos) continue;
                    cmd += " output/" + f;
                }

                Logger::info("Merging files: {}", cmd);
                if (system(cmd.c_str()) != 0) {
                    res.status = 500; 
                    res.set_content("{\"error\":\"Merge failed\"}", "application/json"); 
                    return;
                }
                
                sourcePcap = mergedPath;
                createdTempPcap = true;
            } else {
                // Single file - just use it directly from output/
                sourcePcap = "output/" + files[0];
            }

            // --- STEP 3: CONVERT ---
            std::string finalOutput = "output/export_" + timestamp + "." + format;
            std::string convertCmd = "";

            if (format == "json") {
                // JSON export
                convertCmd = "tshark -r " + sourcePcap + " -T json > " + finalOutput;
            } 
            else if (format == "csv") {
                // CSV Export with your FULL field list
                // [FIX] We use 'sourcePcap' variable here, NOT a hardcoded string
                convertCmd = "tshark -r " + sourcePcap + " -T fields -E separator=, -E header=y -E quote=d "
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
                             // Mode 2 Conf
                             "-e asterix.048_060 " 
                             // Mode 3A
                             "-e asterix.048_070_V -e asterix.048_070_G -e asterix.048_070_L -e asterix.048_070_SQUAWK "
                             // Mode 3A Conf
                             "-e asterix.048_080 "
                             // Flight Level
                             "-e asterix.048_090_V -e asterix.048_090_G -e asterix.048_090_FL "
                             // Mode C
                             "-e asterix.048_100_V -e asterix.048_100_G -e asterix.048_100 " 
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
                             
                             "> " + finalOutput;
            }

            // Logger::info("Converting file: {}", convertCmd);
            int ret = system(convertCmd.c_str());

            // Cleanup
            if (createdTempPcap) {
                remove(sourcePcap.c_str());
            }

            if (ret == 0) {
                nlohmann::json resp;
                resp["url"] = "/api/download?folder=output&name=" + finalOutput.substr(7); 
                res.set_content(resp.dump(), "application/json");
            } else {
                res.status = 500;
                res.set_content("{\"error\": \"Conversion failed. Is tshark installed?\"}", "application/json");
            }

        } catch(...) { res.status = 400; }
    });

    // --- API: DOWNLOAD FILE ---
    m_server.Get("/api/download", [&](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("name")) { res.status=400; return; }
        std::string name = req.get_param_value("name");
        
        // Security check
        if(name.find("..") != std::string::npos || name.find("/") != std::string::npos) {
             res.status=403; return;
        }

        // Determine folder (default to root, or output if specified)
        std::string folder = ".";
        if (req.has_param("folder") && req.get_param_value("folder") == "output") {
            folder = "./output";
        }

        std::string fullPath = folder + "/" + name;
        std::ifstream f(fullPath, std::ios::binary);
        
        if(f) {
            std::stringstream buf; buf << f.rdbuf();
            res.set_content(buf.str(), "application/octet-stream");
            res.set_header("Content-Disposition", "attachment; filename=\""+name+"\"");
        } else {
            Logger::error("Download failed. File not found: {}", fullPath);
            res.status=404;
        }
    });

    // --- API: DELETE FILE ---
    m_server.Post("/api/delete", [&](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("name")) { res.status=400; return; }
        std::string name = req.get_param_value("name");
        
        if(name.find("..") != std::string::npos || name.find("/") != std::string::npos) {
            res.status=403; return;
        }

        std::string fullPath = "./output/" + name;
        if(remove(fullPath.c_str()) == 0) {
            Logger::info("Deleted file: {}", fullPath);
            res.status=200; 
        } else res.status=500;
    });

    // 3. CONFIG
    m_server.Get("/api/config", [&](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json j = m_config; // Uses the INTRUSIVE macro from AppConfig.hpp
        res.set_content(j.dump(), "application/json");
    });

    

    // POST - Frontend updates settings
    m_server.Post("/api/config", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto x = nlohmann::json::parse(req.body);
            
            // 1. UPDATE INTERNAL MEMORY (Flat)
            if(x.contains("rx_port")) m_config.rx_port = x["rx_port"].get<int>();
            if(x.contains("cot_ip")) m_config.cot_ip = x["cot_ip"].get<std::string>(); 
            if(x.contains("cot_port")) m_config.cot_port = x["cot_port"].get<int>(); 
            if(x.contains("cot_proto")) m_config.cot_protocol = x["cot_proto"].get<std::string>();
            if(x.contains("send_sensor_pos")) m_config.send_sensor_pos = x["send_sensor_pos"].get<bool>();
            if(x.contains("tak_output_enabled")) m_config.send_tak_tracks = x["tak_output_enabled"].get<bool>();
            if(x.contains("asterix_output_enabled")) m_config.send_asterix = x["asterix_output_enabled"].get<bool>();
            if(x.contains("asterix_ip")) m_config.asterix_ip = x["asterix_ip"].get<std::string>();
            if(x.contains("asterix_port")) m_config.asterix_port = x["asterix_port"].get<int>();
            
            if(x.contains("ssl_client_pass")) m_config.ssl_client_pass = x["ssl_client_pass"].get<std::string>();
            if(x.contains("ssl_trust_pass")) m_config.ssl_trust_pass = x["ssl_trust_pass"].get<std::string>();
            if(x.contains("ssl_client_cert")) m_config.ssl_client_cert = x["ssl_client_cert"].get<std::string>();
            if(x.contains("ssl_trust_store")) m_config.ssl_trust_store = x["ssl_trust_store"].get<std::string>();

            // 2. CONSTRUCT NESTED JSON FOR FILE SAVE
            nlohmann::json root;
            
            // Preserve System Defaults
            root["system"]["app_name"] = "TARGEX-CLI";
            root["system"]["version"] = "1.0.0";
            root["system"]["webport"] = m_config.rx_port_web;
            root["system"]["isMapActive"] = true;

            // Network Input
            root["network_input"]["interface"] = m_config.interface;
            root["network_input"]["port"] = m_config.rx_port;
            root["network_input"]["protocol"] = "udp"; // Hardcoded for now
            
            // Asterix
            root["AsterixOutput"]["asterix_ip"] = m_config.asterix_ip;
            root["AsterixOutput"]["asterix_port"] = m_config.asterix_port;

            // TAK Output
            root["TAKOutput"]["cot_ip"] = m_config.cot_ip;
            root["TAKOutput"]["cot_port"] = m_config.cot_port;
            root["TAKOutput"]["cot_protocol"] = m_config.cot_protocol;
            root["TAKOutput"]["rx_port"] = m_config.rx_port;
            root["TAKOutput"]["send_asterix"] = m_config.send_asterix;
            root["TAKOutput"]["send_sensor_pos"] = m_config.send_sensor_pos;
            root["TAKOutput"]["send_tak_tracks"] = m_config.send_tak_tracks;
            
            root["TAKOutput"]["ssl_client_cert"] = m_config.ssl_client_cert;
            root["TAKOutput"]["ssl_client_pass"] = m_config.ssl_client_pass;
            root["TAKOutput"]["ssl_trust_pass"] = m_config.ssl_trust_pass;
            root["TAKOutput"]["ssl_trust_store"] = m_config.ssl_trust_store;

            // Save to Disk
            std::ofstream o("config.json");
            o << root.dump(4);
            o.close();

            Logger::info("Config Saved to Nested config.json");
            res.status = 200;
        } catch (...) { res.status = 400; }
    });

    // 4. DATA
    m_server.Get("/api/data", [&](const httplib::Request& req, httplib::Response& res) {
        auto batch = m_engine.pollData();
        nlohmann::json jBatch = batch; 
        res.set_content(jBatch.dump(), "application/json");
    });

    // 5. STATUS
    m_server.Get("/api/status", [&](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json status;
        status["tcp_connected"] = m_engine.isTcpConnected();
        status["protocol"] = m_config.cot_protocol; 
        res.set_content(status.dump(), "application/json");
    });

    // 6. UPLOAD (RAW BINARY MODE) - [FIXED]
    m_server.Post("/api/upload", [&](const httplib::Request& req, httplib::Response& res) {
        // Filename passed via URL: /api/upload?name=client.p12
        std::string filename = "";
        
        // Manual param parsing to be safe across versions
        if (req.has_param("name")) {
             filename = req.get_param_value("name");
        }
        
        if (filename.empty()) {
            res.status = 400;
            res.set_content("Missing 'name' query parameter", "text/plain");
            return;
        }

        std::string filepath = "./" + filename;
        std::ofstream ofs(filepath, std::ios::binary);
        if (ofs) {
            ofs << req.body; // Save the raw binary body directly
            ofs.close();
            Logger::info("File Uploaded: {}", filename);
            res.status = 200;
        } else {
            Logger::error("Failed to save file: {}", filename);
            res.status = 500;
        }
    });
}