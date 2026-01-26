#include "MarsEngine.hpp"
#include "Logger.hpp"
#include <sstream>
#include <ctime>

MarsEngine::MarsEngine() {}

std::string MarsEngine::processPacket(const nlohmann::json& packet) {
    try {
        // 1. Extract ASTERIX Data
        if (!packet.contains("layers") || !packet["layers"].contains("asterix")) {
            return "";
        }
        auto ast = packet["layers"]["asterix"];

        // 2. Identify Track & Position
        // NOTE: You will map your specific Tshark keys here (e.g. asterix_048_042_X)
        // This is just a skeleton to prove the concept.
        
        std::string sac = ast.value("asterix_asterix_048_010_SAC", "0");
        std::string sic = ast.value("asterix_asterix_048_010_SIC", "0");
        std::string trackNum = ast.value("asterix_asterix_048_161_TN", "0");
        
        // Skip if no valid location (example check)
        if (!ast.contains("asterix_asterix_048_042_X")) return "";

        // 3. Generate CoT XML
        // (This is a simplified CoT schema)
        std::stringstream cot;
        cot << "<event version=\"2.0\" uid=\"MARS-" << sac << "-" << sic << "-" << trackNum << "\" "
            << "type=\"a-u-A\" " // Atom-Unknown-Air (We will make this dynamic later)
            << "time=\"" << "2026-01-26T12:00:00Z" << "\" " // Need real timestamp conversion
            << "start=\"" << "2026-01-26T12:00:00Z" << "\" "
            << "stale=\"" << "2026-01-26T12:00:10Z" << "\" "
            << "how=\"m-g\">"
            << "<point lat=\"0.0\" lon=\"0.0\" hae=\"0.0\" ce=\"10.0\" le=\"10.0\"/>"
            << "<detail>"
            << "<contact callsign=\"TRK-" << trackNum << "\"/>"
            << "</detail>"
            << "</event>";

        return cot.str();

    } catch (const std::exception& e) {
        Logger::error("MARS Translation Error: {}", e.what());
        return "";
    }
}