#include "WebServer.hpp"
#include "Logger.hpp"
#include <fstream>
#include <sstream>

WebServer::WebServer(AppConfig& config, MarsEngine& engine) 
    : m_config(config), m_engine(engine) 
{
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

    // 3. CONFIG
    m_server.Post("/api/config", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto x = nlohmann::json::parse(req.body);
            if(x.contains("rx_port")) m_config.rx_port = x["rx_port"].get<int>();
            if(x.contains("cot_ip")) m_config.cot_ip = x["cot_ip"].get<std::string>(); 
            if(x.contains("cot_port")) m_config.cot_port = x["cot_port"].get<int>(); 
            if(x.contains("cot_proto")) m_config.cot_protocol = x["cot_proto"].get<std::string>();
            if(x.contains("send_sensor_pos")) m_config.send_sensor_pos = x["send_sensor_pos"].get<bool>();
            if(x.contains("tak_output_enabled")) m_config.send_tak_tracks = x["tak_output_enabled"].get<bool>();
            if(x.contains("asterix_output_enabled")) m_config.send_asterix = x["asterix_output_enabled"].get<bool>();
            if(x.contains("asterix_ip")) m_config.asterix_ip = x["asterix_ip"].get<std::string>();
            if(x.contains("asterix_port")) m_config.asterix_port = x["asterix_port"].get<int>();
            
            // SSL
            if(x.contains("ssl_client_pass")) m_config.ssl_client_pass = x["ssl_client_pass"].get<std::string>();
            if(x.contains("ssl_trust_pass")) m_config.ssl_trust_pass = x["ssl_trust_pass"].get<std::string>();
            if(x.contains("ssl_client_cert")) m_config.ssl_client_cert = x["ssl_client_cert"].get<std::string>();
            if(x.contains("ssl_trust_store")) m_config.ssl_trust_store = x["ssl_trust_store"].get<std::string>();

            Logger::info("Config Updated.");
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