#pragma once
#include <string>
#include <nlohmann/json.hpp>

// MARS: Monitoring, Analysis, and Recording System
// Responsibility: Convert ASTERIX JSON -> CoT XML
class MarsEngine {
public:
    MarsEngine();
    
    // The main function: Takes a raw packet, returns a CoT XML string (or empty if invalid)
    std::string processPacket(const nlohmann::json& packet);

private:
    // Helper to generate UUIDs for CoT
    std::string generateUUID(const std::string& trackID);
    
    // Helper to determine Identity (Friend/Hostile/Unknown) based on Mode 3/A or IFF
    std::string determineAffiliation(const nlohmann::json& asterix);
};