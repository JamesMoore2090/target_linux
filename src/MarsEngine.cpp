#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    #define sleep(x) Sleep(x * 1000)
    #define usleep(x) Sleep(x / 1000)
    #define popen _popen
    #define pclose _pclose
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "crypt32.lib") // Often needed for OpenSSL on Windows
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h> 
#endif

#include "MarsEngine.hpp"
#include "Logger.hpp"
#include "json.hpp"
#include <iostream>
#include <cstdio>
#include <sstream>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <fcntl.h> 
#include <fstream> 
#include <filesystem>
#include <thread>

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/provider.h> 

namespace fs = std::filesystem;

// --- MATH CONSTANTS ---
constexpr double EARTH_RADIUS_M = 6371000.0;
constexpr double PI = 3.14159265358979323846;
constexpr double NM_TO_M = 1852.0;

// --- HELPERS ---
double toRad(double deg) { return deg * PI / 180.0; }
double toDeg(double rad) { return rad * 180.0 / PI; }

// Thread-safe Time String
std::string getIsoTime(int secondsOffset) {
    auto now = std::time(nullptr) + secondsOffset;
    struct tm buf;
    #ifdef _WIN32
        gmtime_s(&buf, &now);
    #else
        gmtime_r(&now, &buf);
    #endif
    std::stringstream ss;
    ss << std::put_time(&buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string generatePcapName() {
    auto now = std::time(nullptr);
    struct tm buf;
    #ifdef _WIN32
        localtime_s(&buf, &now);
    #else
        localtime_r(&now, &buf);
    #endif
    std::stringstream ss;
    ss << "GNE_" << std::put_time(&buf, "%Y%m%d_%H%M%S") << ".pcap";
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
    // 1. Initialize Winsock (CRITICAL FOR WINDOWS NETWORK)
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Logger::error("[MARS] WSAStartup failed.");
    }
#endif

    // 2. Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
}

MarsEngine::~MarsEngine() { 
    stop(); 
    cleanupSSL();
#ifdef _WIN32
    WSACleanup();
#endif
}

void MarsEngine::start() {
    if (m_isRunning) return;
    m_isRunning = true;
    m_workerThread = std::thread(&MarsEngine::processLoop, this);
    Logger::info("[MARS] Engine Started. Listening on interface: {}", m_config.interface);
}

void MarsEngine::stop() {
    m_isRunning = false;
    
#ifdef _WIN32
    system("taskkill /F /IM tshark.exe /T > NUL 2>&1");
#else
    system("pkill -f 'tshark -l -n -i' > /dev/null 2>&1");
#endif

    if (m_workerThread.joinable()) m_workerThread.join();
    
    if (m_udpSock != -1) {
#ifdef _WIN32
        closesocket(m_udpSock);
#else
        close(m_udpSock);
#endif
        m_udpSock = -1;
    }
    cleanupSSL();
    Logger::info("[MARS] Engine Stopped.");
}

// --- SSL HELPERS ---
void MarsEngine::cleanupSSL() {
    if (m_ssl) { SSL_shutdown(m_ssl); SSL_free(m_ssl); m_ssl = nullptr; }
    if (m_tcpSock != -1) {
#ifdef _WIN32
        closesocket(m_tcpSock);
#else
        close(m_tcpSock);
#endif
        m_tcpSock = -1;
    }
    if (m_sslCtx) { SSL_CTX_free(m_sslCtx); m_sslCtx = nullptr; }
    m_tcpConnected = false;
}

bool MarsEngine::setupSSLContext() {
    if (m_sslCtx) SSL_CTX_free(m_sslCtx);
    
    m_sslCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(m_sslCtx, TLS1_2_VERSION);
    
    if (!m_sslCtx) {
        Logger::error("[SSL] Failed to create SSL Context.");
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
        Logger::error("[SSL] Failed to parse .p12 file.");
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    if (!PKCS12_parse(p12, m_config.ssl_client_pass.c_str(), &pkey, &cert, &ca)) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        Logger::error("[SSL] P12 Decrypt Error: {}", err_buf);
        PKCS12_free(p12);
        return false;
    }
    PKCS12_free(p12);

    if (SSL_CTX_use_certificate(m_sslCtx, cert) != 1 || SSL_CTX_use_PrivateKey(m_sslCtx, pkey) != 1) {
        Logger::error("[SSL] Failed to attach cert/key.");
        return false;
    }
    
    Logger::info("[SSL] Identity Loaded.");
    return true;
}

// --- CONNECTION MANAGER ---
void MarsEngine::manageTcpConnection() {
    if (!m_config.send_tak_tracks && !m_config.send_sensor_pos) {
        if (m_tcpConnected) cleanupSSL();
        return; 
    }

    if (m_config.cot_ip != m_currentHost || m_config.cot_port != m_currentPort) {
        if (m_tcpConnected) cleanupSSL();
        m_currentHost = m_config.cot_ip;
        m_currentPort = m_config.cot_port;
    }

    if (m_tcpConnected) return;

    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - m_lastTcpAttempt).count() < 5) return;
    m_lastTcpAttempt = now;

    bool useSSL = (m_config.cot_protocol == "ssl");
    if (useSSL && !m_sslCtx) {
        if (!setupSSLContext()) return; 
    }

    Logger::info("[MARS] Connecting to TAK: {}:{}", m_currentHost, m_currentPort);

    m_tcpSock = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (m_tcpSock < 0) return;

#ifdef _WIN32
    DWORD timeout = 2000;
    setsockopt(m_tcpSock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval timeout; timeout.tv_sec = 2; timeout.tv_usec = 0;
    setsockopt(m_tcpSock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(m_currentPort);
    inet_pton(AF_INET, m_currentHost.c_str(), &serv_addr.sin_addr);

    if (connect(m_tcpSock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        Logger::error("[MARS] TCP Connection Failed.");
#ifdef _WIN32
        closesocket(m_tcpSock);
#else
        close(m_tcpSock);
#endif
        m_tcpSock = -1;
        return;
    }

    if (useSSL) {
        m_ssl = SSL_new(m_sslCtx);
        SSL_set_fd(m_ssl, m_tcpSock);
        if (SSL_connect(m_ssl) <= 0) {
            Logger::error("[MARS] SSL Handshake Failed.");
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
                ret = SSL_write(m_ssl, payload.c_str(), (int)payload.length());
            } else {
                ret = send(m_tcpSock, payload.c_str(), (int)payload.length(), 0);
            }
            if (ret <= 0) cleanupSSL(); 
        }
    } 
    else {
        // UDP Send
        struct sockaddr_in udpAddr;
        memset(&udpAddr, 0, sizeof(udpAddr));
        udpAddr.sin_family = AF_INET;
        udpAddr.sin_port = htons(m_config.cot_port);
        inet_pton(AF_INET, m_config.cot_ip.c_str(), &udpAddr.sin_addr);
        
        // Use m_udpSock which is initialized in processLoop, OR create a temp one
        // For reliability, we'll create a temp one here if m_udpSock isn't ready
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        sendto(s, xml.c_str(), (int)xml.length(), 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
}

void MarsEngine::processLoop() {
    // 1. Setup Directories
    namespace fs = std::filesystem;
    fs::path outputDir = fs::absolute("output");
    if (!fs::exists(outputDir)) {
        try { fs::create_directories(outputDir); } 
        catch (...) { Logger::error("[MARS] Failed to create output dir!"); return; }
    }
    
    std::string pcapFile = (outputDir / generatePcapName()).string();
    std::string filter = "udp port " + std::to_string(m_config.rx_port);
    std::string tsharkBin = "\"C:\\Program Files\\Wireshark\\tshark.exe\"";
    
    // [FIX 1] Removed '-P' to ensure we only get clean JSON. 
    // We rely on '-l' for buffering and '< NUL' for handle safety.
    std::string tsharkCmd = tsharkBin + 
                            " -l -n -i \"" + m_config.interface + "\"" + 
                            " -f \"" + filter + "\"" +
                            " -w \"" + pcapFile + "\"" + 
                            " -T ek -d udp.port==" + std::to_string(m_config.rx_port) + ",asterix";

    // 2. Batch File Wrapper
    std::string batPath = "run_capture.bat";
    std::ofstream batFile(batPath);
    if (batFile.is_open()) {
        batFile << "@echo off\n";
        batFile << tsharkCmd << " < NUL 2>&1\n"; 
        batFile.close();
    } else {
        Logger::error("[MARS] Failed to create batch file!");
        return;
    }

    Logger::info("[MARS] Writing PCAP to: {}", pcapFile);

    // 3. Execute
#ifdef _WIN32
    FILE* pipe = _popen("cmd.exe /C run_capture.bat", "rb");
#else
    FILE* pipe = popen("./run_capture.bat", "r");
#endif

    if (!pipe) {
        Logger::error("[MARS] Failed to open pipe!");
        return;
    }

    char buffer[65536]; 
    std::string accumulator = "";
    auto lastOriginCoT = std::chrono::steady_clock::now();

    while (m_isRunning) {
        size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, pipe);
        
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            accumulator += buffer;

            size_t pos = 0;
            while ((pos = accumulator.find('\n')) != std::string::npos) {
                std::string line = accumulator.substr(0, pos);
                accumulator.erase(0, pos + 1);

                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.length() < 5) continue;
                // --- [DEBUG] DUMP RAW JSON ---
                Logger::debug("[RAW] {}", line);
                try {
                    // Check for Tshark errors before parsing
                    if (line.find("Access is denied") != std::string::npos) {
                         Logger::error("[MARS] PERMISSION ERROR: {}", line);
                    }

                    nlohmann::json root = nlohmann::json::parse(line);
                    
                    if (root.contains("index")) continue;
                    if (!root.contains("layers") || !root["layers"].contains("asterix")) continue;

                    // [FIX 2] Push to Web Queue IMMEDIATELY (Before any complex logic can fail)
                    {
                        std::lock_guard<std::mutex> lock(m_queueMutex);
                        m_webQueue.push_back(root);
                        if(m_webQueue.size() > 500) m_webQueue.pop_front();
                    }

                    // ==========================================
                    //      DATA EXTRACTION (ROBUST METHOD)
                    // ==========================================
                    auto ast = root["layers"]["asterix"];
                    std::string id = "";
                    double lat=0, lon=0, rho=-1, theta=0, alt_ft=0;
                    bool isGeo=false, isPolar=false;
                    
                    for (auto& [key, val] : ast.items()) {
                        if (key.find("120_LAT")!=std::string::npos) { lat=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isGeo=true; }
                        if (key.find("120_LON")!=std::string::npos) { lon=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isGeo=true; }
                        if (key.find("040_RHO")!=std::string::npos) { rho=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isPolar=true; }
                        if (key.find("040_THETA")!=std::string::npos) { theta=val.is_string()?std::stod(val.get<std::string>()):val.get<double>(); isPolar=true; }
                        // --- ID / CALLSIGN ---
                        if (key.find("161_TN") != std::string::npos || key.find("161_TRN") != std::string::npos) {
                            if(val.is_number()) id = std::to_string(val.get<int>());
                            else if(val.is_string()) id = val.get<std::string>();
                        }
                }

                    // --- UPDATE SENSOR ORIGIN ---
                    // If we have a Geo point but no ID (or ID=0), it's likely the sensor status message (Cat 34)
                    if (isGeo && (id.empty() || id == "0")) {
                        m_sensorLat = lat; m_sensorLon = lon; m_hasOrigin = true;
                    }

                    // --- OUTPUT TO TAK ---
                    if (m_config.send_tak_tracks && !id.empty()) {
                        double trkLat=0, trkLon=0;
                        bool ready = false;

                        if (isGeo) { 
                            trkLat = lat; trkLon = lon; ready = true; 
                        }
                        else if (isPolar && m_hasOrigin && rho >= 0) { 
                            polarToGeo(m_sensorLat, m_sensorLon, rho, theta, trkLat, trkLon);
                            ready = true; 
                        }

                        if (ready) {
                            std::stringstream xml;
                            xml << "<event version='2.0' uid='GNE-TRK-" << id << "' type='a-u-G' how='m-g' time='" << getIsoTime(0) << "' start='" << getIsoTime(0) << "' stale='" << getIsoTime(10) << "'>"
                                << "<point lat='" << trkLat << "' lon='" << trkLon << "' hae='" << (alt_ft*0.3048) << "' ce='25' le='25'/>"
                                << "<detail><contact callsign='TN" << id << "'/></detail></event>";
                            
                            sendToTak(xml.str());
                        }
                    }

                } catch (...) {
                    // Ignore parsing errors for individual packets to keep the stream alive
                }
            }
        } else {
             if (feof(pipe)) { Logger::warn("[MARS] EOF."); break; }
             std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // --- HEARTBEAT / SENSOR PPLI ---
        if (m_config.send_sensor_pos && m_hasOrigin) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastOriginCoT).count() >= 10) {
                std::stringstream xml;
                xml << "<event version='2.0' uid='SENSOR-ORIGIN' type='a-f-G-U-H' how='m-g' time='" << getIsoTime(0) << "' start='" << getIsoTime(0) << "' stale='" << getIsoTime(20) << "'>"
                    << "<point lat='" << m_sensorLat << "' lon='" << m_sensorLon << "' hae='0' ce='10' le='10'/>"
                    << "<detail><contact callsign='GNE-SENSOR'/></detail></event>";
                sendToTak(xml.str());
                lastOriginCoT = now;
            }
        }
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    Logger::info("[MARS] Capture stopped.");
}

std::vector<nlohmann::json> MarsEngine::pollData() {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    if (m_webQueue.empty()) return {};
    std::vector<nlohmann::json> batch(m_webQueue.begin(), m_webQueue.end());
    m_webQueue.clear();
    return batch;
}