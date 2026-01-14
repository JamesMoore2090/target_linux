#pragma once // Prevents this file from being included twice by accident
#include <string>
#include <vector>
#include <atomic>
#include <cstdio> // Required for FILE*
#include "ConfigLoader.hpp"
#include <nlohmann/json.hpp> // We parse JSON immediately now

using json = nlohmann::json;
    
// This class represents the "Engine" of your server
class TargexCore {
public:

    // Constructor and Destructor
    explicit TargexCore(const AppConfig& config);
    ~TargexCore();

    // The main setup function. Returns true if successful.
    bool initialize();
    // Main operational functions
    json pollData();
    void startCapture();
    void stopCapture();
    bool isCapturing() const { return m_isCapturing; }
    std::string getActiveFilename() const { return m_currentFile; }
    

private:
    const AppConfig m_config;
    
    // The "Handle" to the running Tshark process
    FILE* m_tsharkPipe; 
    
    // A buffer to hold one line of text from Tshark
    // Tshark lines can be long, so we allocate a safe amount (64KB)
    char m_lineBuffer[65536];
    std::atomic<bool> m_isCapturing{false};
    std::string m_currentFile;
};