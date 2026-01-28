#include "MarsEngine.hpp"
#include "Logger.hpp"
#include <iostream>
#include <sstream>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <thread>
#include <chrono> // For Timing Logs

const double SENSOR_LAT = 38.5134;
const double SENSOR_LON = -77.3008;

// --- HELPERS ---

static double parseJsonFloat(const nlohmann::json& val) {
    try {
        if (val.is_array() && !val.empty()) {
            if (val[0].is_string()) return std::stod(val[0].get<std::string>());
            if (val[0].is_number()) return val[0].get<double>();
        }
        if (val.is_string()) return std::stod(val.get<std::string>());
        if (val.is_number()) return val.get<double>();
    } catch (...) {}
    return 0.0;
}

static std::string getKeyStr(const nlohmann::json& ast, const std::string& suffix) {
    std::string k1 = "asterix_asterix_" + suffix;
    std::string k2 = "asterix_" + suffix;
    if (ast.contains(k1)) return ast[k1].get<std::string>();
    if (ast.contains(k2)) return ast[k2].get<std::string>();
    return "";
}

static double getKeyFloat(const nlohmann::json& ast, const std::string& suffix) {
    std::string k1 = "asterix_asterix_" + suffix;
    std::string k2 = "asterix_" + suffix;
    if (ast.contains(k1)) return parseJsonFloat(ast[k1]);
    if (ast.contains(k2)) return parseJsonFloat(ast[k2]);
    return 0.0;
}

static std::string getCurrentTimeISO(int secondsOffset = 0) {
    time_t now;
    time(&now);
    now += secondsOffset;
    struct tm tstruct;
    char buf[80];
    tstruct = *gmtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tstruct);
    return std::string(buf);
}

// --- CLASS IMPLEMENTATION ---

MarsEngine::MarsEngine() : m_sockFd(-1), m_sslCtx(nullptr), m_ssl(nullptr), m_connStatus("ready") {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");
}

MarsEngine::~MarsEngine() {
    cleanupSSL();
    if (m_sockFd >= 0) close(m_sockFd);
}

// --- FIX 1: FAST CLEANUP (Don't wait for polite goodbye) ---
void MarsEngine::cleanupSSL() {
    if (m_ssl) { 
        // Tell OpenSSL we are done, don't try to send/receive shutdown alerts
        SSL_set_quiet_shutdown(m_ssl, 1); 
        SSL_free(m_ssl); 
        m_ssl = nullptr; 
    }
    if (m_sslCtx) { 
        SSL_CTX_free(m_sslCtx); 
        m_sslCtx = nullptr; 
    }
}

void MarsEngine::updateConfig(const CoTConfig& newConfig) {
    if (newConfig.ip == "239.2.3.1" && m_config.ip != "239.2.3.1" && !newConfig.clientP12Path.empty()) {
        // preserve IP
    } else {
        m_config.ip = newConfig.ip;
        m_config.port = newConfig.port;
        m_config.protocol = newConfig.protocol;
    }

    if (!newConfig.clientP12Path.empty()) {
        m_config.clientP12Path = newConfig.clientP12Path;
        m_config.clientPwd = newConfig.clientPwd;
        m_config.trustP12Path = newConfig.trustP12Path;
        m_config.trustPwd = newConfig.trustPwd;
    }

    if (m_config.protocol == "ssl" && (m_config.clientP12Path.empty() || m_config.trustP12Path.empty())) {
        Logger::info("MARS: SSL Configured, waiting for certificates...");
        return; 
    }

    Logger::info("MARS: Applying Config (Proto: {}, IP: {})", m_config.protocol, m_config.ip);
    initSocket(); 
}

void MarsEngine::updateStatus(const std::string& status) {
    {
        // Lock while writing to protect against the Web Server reading at the same time
        std::lock_guard<std::mutex> lock(m_statusMutex);
        m_connStatus = status;
    }

    // Call callback outside the lock to prevent deadlocks if the callback is slow
    if (m_statusCallback) m_statusCallback(status);
}

// --- P12 LOADER (Unchanged, omitted for brevity but KEEP IT from previous step) ---
// (Paste the 'loadP12' function from the previous turn here. It is robust and correct.)
// ... (Include loadP12 here) ... 
bool loadP12(SSL_CTX* ctx, const std::string& path, const std::string& pwd, bool isTrustStore) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) { Logger::error("MARS: Could not open P12 file: {}", path); return false; }
    PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) { Logger::error("MARS: Failed to parse P12."); return false; }
    EVP_PKEY* pkey = nullptr; X509* cert = nullptr; STACK_OF(X509)* ca = nullptr;
    if (!PKCS12_parse(p12, pwd.c_str(), &pkey, &cert, &ca)) {
        Logger::error("MARS: Failed to decrypt P12."); PKCS12_free(p12); return false;
    }
    PKCS12_free(p12);

    if (isTrustStore) {
        X509_STORE* store = SSL_CTX_get_cert_store(ctx);
        int count = 0;
        if (cert) { X509_STORE_add_cert(store, cert); count++; }
        if (ca) { for(int i=0; i<sk_X509_num(ca); i++) { X509_STORE_add_cert(store, sk_X509_value(ca, i)); count++; } }
        Logger::info("MARS: Loaded {} CA certificates.", count);
        return true;
    }

    if (cert) {
        char subj[256]; X509_NAME_oneline(X509_get_subject_name(cert), subj, 256);
        Logger::info("MARS: Loaded Identity: {}", subj);
        SSL_CTX_use_certificate(ctx, cert);
    }
    if (pkey) SSL_CTX_use_PrivateKey(ctx, pkey);
    if (ca) { for(int i=0; i<sk_X509_num(ca); i++) SSL_CTX_add_extra_chain_cert(ctx, X509_dup(sk_X509_value(ca, i))); }

    if (!SSL_CTX_check_private_key(ctx)) { Logger::error("MARS: Key/Cert Mismatch!"); return false; }
    return true;
}

// --- INITIALIZATION (With Timing Logs) ---
void MarsEngine::initSocket() {
    auto t1 = std::chrono::steady_clock::now(); // Start Timer

    cleanupSSL();
    if (m_sockFd >= 0) { close(m_sockFd); m_sockFd = -1; }
    updateStatus("connecting");

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(m_config.port);

    if (inet_pton(AF_INET, m_config.ip.c_str(), &serv_addr.sin_addr) <= 0) {
        Logger::error("MARS: Invalid IP Address");
        updateStatus("failed");
        return;
    }

    if (m_config.protocol == "udp") {
        if ((m_sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return;
        updateStatus("ready");
    } 
    else if (m_config.protocol == "tcp" || m_config.protocol == "ssl") {
        
        // 1. Create Socket
        if ((m_sockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return;

        // 2. Connect TCP (LOG TIMING)
        Logger::info("MARS: Attempting TCP Connect...");
        if (connect(m_sockFd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            Logger::error("MARS: TCP Connect Failed");
            updateStatus("failed");
            return;
        }
        
        auto t2 = std::chrono::steady_clock::now();
        Logger::info("MARS: TCP Connected (took {}ms)", std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count());

        if (m_config.protocol == "ssl") {
            Logger::info("MARS: Starting SSL Handshake...");
            if (!initSSL()) {
                updateStatus("failed");
                close(m_sockFd);
                m_sockFd = -1;
                return;
            }
            auto t3 = std::chrono::steady_clock::now();
            Logger::info("MARS: SSL Handshake Complete (took {}ms)", std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count());
        }
        
        updateStatus("connected");

        // HEARTBEAT
        std::thread([this]() {
            while (m_connStatus == "connected") {
                std::string now = getCurrentTimeISO(0);
                std::string stale = getCurrentTimeISO(120);
                std::stringstream hb;
                hb << "<event version=\"2.0\" uid=\"TARGEX-HEARTBEAT\" type=\"a-f-G-E-V\" "
                   << "time=\"" << now << "\" start=\"" << now << "\" stale=\"" << stale << "\" how=\"h-g-i-g-o\">"
                   << "<point lat=\"" << SENSOR_LAT << "\" lon=\"" << SENSOR_LON << "\" hae=\"0.0\" ce=\"999\" le=\"999\"/>"
                   << "<detail><status readiness=\"true\"/></detail></event>";
                this->sendData(hb.str());
                sleep(15);
            }
        }).detach();
    }
}

bool MarsEngine::initSSL() {
    m_sslCtx = SSL_CTX_new(TLS_client_method());
    if (!m_sslCtx) return false;

    if (!m_config.clientP12Path.empty()) {
        if (!loadP12(m_sslCtx, m_config.clientP12Path, m_config.clientPwd, false)) return false;
    }
    if (!m_config.trustP12Path.empty()) {
        if (!loadP12(m_sslCtx, m_config.trustP12Path, m_config.trustPwd, true)) return false;
    }

    m_ssl = SSL_new(m_sslCtx);
    SSL_set_fd(m_ssl, m_sockFd);
    
    // Handshake
    if (SSL_connect(m_ssl) <= 0) {
        Logger::error("MARS: SSL Handshake Failed. (Check Certificates)");
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

void MarsEngine::sendData(const std::string& data) {
    if (m_config.protocol == "ssl" && m_ssl) {
        SSL_write(m_ssl, data.c_str(), data.size());
    } else if (m_sockFd >= 0) {
        if (m_config.protocol == "udp") {
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_port = htons(m_config.port);
            inet_pton(AF_INET, m_config.ip.c_str(), &dest.sin_addr);
            sendto(m_sockFd, data.c_str(), data.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
        } else {
            send(m_sockFd, data.c_str(), data.size(), 0);
        }
    }
}

void MarsEngine::processAndSend(const nlohmann::json& packet) {
    if (!packet.contains("layers") || !packet["layers"].contains("asterix")) return;
    std::string cotXml = generateCoT(packet["layers"]["asterix"]);
    if (!cotXml.empty()) sendData(cotXml);
}

MarsEngine::GeoPoint MarsEngine::calculateLatLon(double rangeNM, double bearingDeg) {
    const double R = 3440.065; 
    double lat1 = SENSOR_LAT * (M_PI / 180.0);
    double lon1 = SENSOR_LON * (M_PI / 180.0);
    double brng = bearingDeg * (M_PI / 180.0);
    double dr = rangeNM / R;
    double lat2 = asin(sin(lat1)*cos(dr) + cos(lat1)*sin(dr)*cos(brng));
    double lon2 = lon1 + atan2(sin(brng)*sin(dr)*cos(lat1), cos(dr)-sin(lat1)*sin(lat2));
    return { lat2 * (180.0 / M_PI), lon2 * (180.0 / M_PI) };
}

std::string MarsEngine::generateCoT(const nlohmann::json& ast) {
    std::string trackId = getKeyStr(ast, "048_161_TN");
    if (trackId.empty()) trackId = getKeyStr(ast, "034_161_TN");
    if (trackId.empty()) trackId = "UNK";
    if (trackId.front() == '[') {
        size_t end = trackId.find(',');
        if (end == std::string::npos) end = trackId.find(']');
        if (end != std::string::npos) trackId = trackId.substr(1, end - 1);
    }

    double lat = 0.0, lon = 0.0;
    bool validPos = false;
    double cat34Lat = getKeyFloat(ast, "034_120_LAT");
    double cat34Lon = getKeyFloat(ast, "034_120_LON");
    
    if (cat34Lat != 0.0 || cat34Lon != 0.0) {
        lat = cat34Lat; lon = cat34Lon; validPos = true;
    } else {
        double rho = getKeyFloat(ast, "048_040_RHO");
        double theta = getKeyFloat(ast, "048_040_THETA");
        if (ast.contains("asterix_asterix_048_040_RHO") || ast.contains("asterix_048_040_RHO")) {
            GeoPoint p = calculateLatLon(rho, theta);
            lat = p.lat; lon = p.lon; validPos = true;
        }
    }

    if (!validPos) return "";

    // --- UPDATED TIMESTAMP (Future Stale) ---
    std::string now = getCurrentTimeISO(0);
    std::string stale = getCurrentTimeISO(120);

    std::stringstream ss;
    ss << "<event version=\"2.0\" uid=\"TARGEX-" << trackId << "\" type=\"a-u-S\" " 
       << "time=\"" << now << "\" start=\"" << now << "\" stale=\"" << stale << "\" how=\"m-g\">"
       << "<point lat=\"" << lat << "\" lon=\"" << lon << "\" hae=\"0.0\" ce=\"10.0\" le=\"10.0\"/>"
       << "<detail><contact callsign=\"TRK-" << trackId << "\"/><remarks>Sea Surface</remarks></detail></event>";
    return ss.str();
}