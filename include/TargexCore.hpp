#ifndef TARGEX_CORE_HPP
#define TARGEX_CORE_HPP

#include "ConfigLoader.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <deque> // For the queue
#include <nlohmann/json.hpp>

class TargexCore {
public:
    TargexCore(const AppConfig& config);
    ~TargexCore();

    bool initialize();
    void startCapture();
    void stopCapture();

    // Now simply pops from the queue
    nlohmann::json pollData();

private:
    AppConfig m_config;
    FILE* m_tsharkPipe = nullptr;
    std::mutex m_pipeMutex;
    std::atomic<bool> m_isCapturing{false};
    std::string m_currentFile;

    // --- NEW: Threaded Buffer ---
    std::thread m_captureThread;
    std::deque<nlohmann::json> m_packetQueue;
    std::mutex m_queueMutex;
    
    // The loop function for the background thread
    void captureLoop(); 
};

#endif