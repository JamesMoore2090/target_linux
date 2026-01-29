#include "MarsEngine.hpp"
#include "Logger.hpp"
#include <iostream>
#include <cstdio>
#include <sstream>
#include <cmath>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctime>
#include <iomanip>
#include <unistd.h> 
#include <fcntl.h> 
#include <fstream> 

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/provider.h> // [NEW] Required for Legacy Provider

// --- MATH CONSTANTS ---
constexpr double EARTH_RADIUS_M = 6371000.0;
constexpr double PI = 3.14159265358979323846;
constexpr double NM_TO_M = 1852.0;

// --- HELPERS ---
double toRad(double deg) { return deg * PI / 180.0; }
double toDeg(double rad) { return rad * 180.0 / PI; }

std::string getIsoTime(int secondsOffset) {
    std::time_t now = std::time(nullptr) + secondsOffset;
    std::tm* t = std::gmtime(&now);
    std::stringstream ss;
    ss << std::put_time(t, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

void polarToGeo(double sensorLat, double sensorLon, double rangeNm, double azDeg, double& outLat, double& outLon) {
    double rngM = rangeNm * NM_TO_M;
    double angDist = rngM / EARTH_RADIUS_M;
    double lat1 = toRad(sensorLat);
    double lon1 = toRad(sensorLon);
    double brng = toRad(azDeg);
    double lat2 = asin(sin(lat1) * cos(angDist) + cos(lat1) * sin(angDist) * cos(brng));
    double lon2 = lon1 + atan2(sin(brng) * sin(angDist) * cos(lat1), cos(angDist) - sin(lat1) * sin(lat2));
    outLat = toDeg(lat2);
    outLon = toDeg(lon2);
}

// --- CONSTRUCTOR/DESTRUCTOR ---
MarsEngine::MarsEngine(AppConfig& config) : m_config(config) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // [FIX] LOAD LEGACY PROVIDER FOR OLD P12 FILES
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
}

MarsEngine::~MarsEngine() { 
    stop(); 
    cleanupSSL();
}

void MarsEngine::start() {
    if (m_isRunning) return;
    m_isRunning = true;
    m_workerThread = std::thread(&MarsEngine::processLoop, this);
    Logger::info("[MARS] Engine Started. Listening on interface: {}", m_config.interface);
}

void MarsEngine::stop() {
    m_isRunning = false;
    if (system("pkill -f 'tshark -l -n -i'") != 0) {} 
    if (m_workerThread.joinable()) m_workerThread.join();
    if (m_udpSock != -1) close(m_udpSock);
    cleanupSSL();
    Logger::info("[MARS] Engine Stopped.");
}

// --- SSL HELPERS ---
void MarsEngine::cleanupSSL() {
    if (m_ssl) { SSL_shutdown(m_ssl); SSL_free(m_ssl); m_ssl = nullptr; }
    if (m_tcpSock != -1) { close(m_tcpSock); m_tcpSock = -1; }
    if (m_sslCtx) { SSL_CTX_free(m_sslCtx); m_sslCtx = nullptr; }
    m_tcpConnected = false;
}

bool MarsEngine::setupSSLContext() {
    if (m_sslCtx) SSL_CTX_free(m_sslCtx);
    
    // [FIX] Force TLS 1.2 Method (More compatible with TAK Server)
    m_sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(m_sslCtx, TLS1_2_VERSION);
    
    if (!m_sslCtx) {
        Logger::error("[SSL] Failed to create SSL Context.");
        return false;
    }

    std::ifstream f(m_config.ssl_client_cert);
    if (!f.good()) {
        Logger::error("[SSL] Certificate file NOT FOUND: '{}'. Please ensure it is in the run directory.", m_config.ssl_client_cert);
        return false;
    }

    FILE* fp = fopen(m_config.ssl_client_cert.c_str(), "rb");
    if (!fp) {
        Logger::error("[SSL] Could not read .p12 file: {}", m_config.ssl_client_cert);
        return false;
    }

    PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (!p12) {
        Logger::error("[SSL] Failed to parse .p12 file. (Legacy format?)");
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    if (!PKCS12_parse(p12, m_config.ssl_client_pass.c_str(), &pkey, &cert, &ca)) {
        // [DEBUG] Print actual OpenSSL error to help debug
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        Logger::error("[SSL] Failed to decrypt .p12. OpenSSL Error: {}", err_buf);
        
        PKCS12_free(p12);
        return false;
    }
    PKCS12_free(p12);

    if (SSL_CTX_use_certificate(m_sslCtx, cert) != 1 || SSL_CTX_use_PrivateKey(m_sslCtx, pkey) != 1) {
        Logger::error("[SSL] Failed to attach cert/key to Context.");
        return false;
    }
    
    Logger::info("[SSL] Loaded Identity: {}", m_config.ssl_client_cert);
    return true;
}

// --- CONNECTION MANAGER ---
void MarsEngine::manageTcpConnection() {
    if (!m_config.send_tak_tracks && !m_config.send_sensor_pos) {
        if (m_tcpConnected) {
            Logger::info("[MARS] Output disabled. Disconnecting...");
            cleanupSSL();
        }
        return; 
    }

    if (m_config.cot_ip != m_currentHost || m_config.cot_port != m_currentPort) {
        if (m_tcpConnected) {
            Logger::info("[MARS] Config changed, reconnecting...");
            cleanupSSL();
        }
        m_currentHost = m_config.cot_ip;
        m_currentPort = m_config.cot_port;
    }

    if (m_tcpConnected) return;

    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - m_lastTcpAttempt).count() < 5) return;
    m_lastTcpAttempt = now;

    bool useSSL = (m_config.cot_protocol == "ssl");
    if (useSSL && !m_sslCtx) {
        if (!setupSSLContext()) {
             return; 
        }
    }

    Logger::info("[MARS] Connecting to {}:{} ({})...", m_currentHost, m_currentPort, useSSL ? "SSL" : "TCP");
    
    m_tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (m_tcpSock < 0) return;

    struct timeval timeout; timeout.tv_sec = 2; timeout.tv_usec = 0;
    setsockopt(m_tcpSock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(m_currentPort);
    inet_pton(AF_INET, m_currentHost.c_str(), &serv_addr.sin_addr);

    if (connect(m_tcpSock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        Logger::error("[MARS] TCP Connection Failed.");
        close(m_tcpSock); m_tcpSock = -1;
        return;
    }

    if (useSSL) {
        m_ssl = SSL_new(m_sslCtx);
        SSL_set_fd(m_ssl, m_tcpSock);
        
        if (SSL_connect(m_ssl) <= 0) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            Logger::error("[MARS] SSL Handshake Failed: {}", err_buf);
            
            cleanupSSL();
            return;
        }
        Logger::info("[MARS] SSL Handshake Success!");
    } else {
        Logger::info("[MARS] TCP Connected.");
    }

    m_tcpConnected = true;
}

// --- SEND HELPER ---
void MarsEngine::sendToTak(const std::string& xml) {
    if (!m_config.send_tak_tracks && !m_config.send_sensor_pos) return;

    if (m_config.cot_protocol == "tcp" || m_config.cot_protocol == "ssl") {
        manageTcpConnection();
        
        if (m_tcpConnected) {
            std::string payload = xml + "\n";
            int ret = -1;

            if (m_config.cot_protocol == "ssl" && m_ssl) {
                ret = SSL_write(m_ssl, payload.c_str(), payload.length());
            } else {
                ret = send(m_tcpSock, payload.c_str(), payload.length(), 0);
            }
            
            if (ret <= 0) {
                Logger::error("[MARS] Send failed. Reconnecting...");
                cleanupSSL(); 
            }
        }
    } 
    else {
        struct sockaddr_in udpAddr;
        memset(&udpAddr, 0, sizeof(udpAddr));
        udpAddr.sin_family = AF_INET;
        udpAddr.sin_port = htons(m_config.cot_port);
        inet_pton(AF_INET, m_config.cot_ip.c_str(), &udpAddr.sin_addr);
        sendto(m_udpSock, xml.c_str(), xml.length(), 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
    }
}

// --- PROCESS LOOP ---
void MarsEngine::processLoop() {
    m_udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    char loop=1; setsockopt(m_udpSock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    unsigned char ttl=64; setsockopt(m_udpSock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    int bcast=1; setsockopt(m_udpSock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    int sockAst = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(sockAst, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
    struct sockaddr_in astAddr;

    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    std::string cmd = "tshark -l -n -i " + m_config.interface + " -f \"" + filter + "\" "
                      "-T ek -d udp.port==" + std::to_string(m_config.rx_port) + ",asterix";

    Logger::info("[MARS] Launching Tshark: {}", cmd);
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) { Logger::error("[MARS] Failed to start Tshark!"); return; }

    char buffer[65536];
    auto lastOriginCoT = std::chrono::steady_clock::now();

    while (m_isRunning && pipe) {
        memset(&astAddr, 0, sizeof(astAddr)); 
        astAddr.sin_family=AF_INET; 
        astAddr.sin_port=htons(m_config.asterix_port); 
        inet_pton(AF_INET, m_config.asterix_ip.c_str(), &astAddr.sin_addr);

        if(m_config.cot_protocol != "udp") manageTcpConnection();

        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            try {
                if (m_config.send_asterix) {
                     std::string jsonStr(buffer);
                     sendto(sockAst, jsonStr.c_str(), jsonStr.length(), 0, (struct sockaddr*)&astAddr, sizeof(astAddr));
                }

                nlohmann::json raw = nlohmann::json::parse(buffer);
                if (!raw.contains("layers") || !raw["layers"].contains("asterix")) continue;

                {
                    std::lock_guard<std::mutex> lock(m_queueMutex);
                    m_webQueue.push_back(raw);
                    if(m_webQueue.size() > 500) m_webQueue.pop_front();
                }

                auto ast = raw["layers"]["asterix"];
                std::string id = "";
                double lat=0, lon=0, rho=-1, theta=0;
                bool isGeo=false, isPolar=false;

                for (auto& [key, val] : ast.items()) {
                    if (key.find("120_LAT")!=std::string::npos) { lat=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isGeo=true; }
                    if (key.find("120_LON")!=std::string::npos) { lon=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isGeo=true; }
                    if (key.find("040_RHO")!=std::string::npos) { rho=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isPolar=true; }
                    if (key.find("040_THETA")!=std::string::npos) { theta=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isPolar=true; }
                    if (key.find("161_TN")!=std::string::npos) {
                        if(val.is_number()) id=std::to_string(val.get<int>());
                        else if(val.is_string()) id=val.get<std::string>();
                    }
                }

                if (isGeo && (id.empty() || id == "0")) {
                    m_sensorLat = lat; m_sensorLon = lon; m_hasOrigin = true;
                }

                if (m_config.send_tak_tracks && !id.empty()) {
                    double trkLat=0, trkLon=0; 
                    bool ready=false;
                    if (isGeo) { trkLat=lat; trkLon=lon; ready=true; }
                    else if (isPolar && m_hasOrigin && rho>=0) { 
                        polarToGeo(m_sensorLat, m_sensorLon, rho, theta, trkLat, trkLon); 
                        ready=true; 
                    }
                    if (ready) {
                        std::stringstream xml;
                        xml << "<event version='2.0' uid='TRK-" << id << "' type='a-u-G' how='m-g' time='" << getIsoTime(0) << "' start='" << getIsoTime(0) << "' stale='" << getIsoTime(5) << "'>"
                            << "<point lat='" << trkLat << "' lon='" << trkLon << "' hae='0' ce='25' le='25'/>"
                            << "<detail><contact callsign='Track " << id << "'/></detail></event>";
                        sendToTak(xml.str());
                    }
                }
            } catch (...) {}
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        if (m_config.send_sensor_pos && m_hasOrigin) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastOriginCoT).count() >= 10) {
                std::stringstream xml;
                xml << "<event version='2.0' uid='SENSOR-ORIGIN' type='a-f-G-U-C' how='m-g' time='" << getIsoTime(0) << "' start='" << getIsoTime(0) << "' stale='" << getIsoTime(20) << "'>"
                    << "<point lat='" << m_sensorLat << "' lon='" << m_sensorLon << "' hae='0' ce='10' le='10'/>"
                    << "<detail><contact callsign='ASTERIX SENSOR'/></detail></event>";
                sendToTak(xml.str());
                lastOriginCoT = now;
            }
        }
    }
    pclose(pipe);
    cleanupSSL();
    close(sockAst);
}

std::vector<nlohmann::json> MarsEngine::pollData() {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    if (m_webQueue.empty()) return {};
    std::vector<nlohmann::json> batch(m_webQueue.begin(), m_webQueue.end());
    m_webQueue.clear();
    return batch;
}