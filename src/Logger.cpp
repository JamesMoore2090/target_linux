#include "Logger.hpp"
#include <spdlog/sinks/stdout_color_sinks.h> // For CLI
#include <spdlog/sinks/basic_file_sink.h>    // For File
#include <vector>
#include <iostream>

std::shared_ptr<spdlog::logger> Logger::s_Logger;

std::shared_ptr<spdlog::logger> createConsoleOnlyLogger() {
    auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("FALLBACK", console);
    logger->set_level(spdlog::level::info);
    return logger;
}

void Logger::init(const std::string& filePath, const std::string& logLevel) {
    try {
        // 1. Create the Console Sink (Colorized output)
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::trace); // Console always shows everything allowed by global level
        console_sink->set_pattern("%^[%T] %n: %v%$"); // Pattern: [Time] Name: Message

        // 2. Create the File Sink
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(filePath, true);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v"); // Detailed timestamp for files

        // 3. Combine them into a Multi-Sink Logger
        std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
        s_Logger = std::make_shared<spdlog::logger>("TARGEX", sinks.begin(), sinks.end());

        // 4. Set Global Log Level
        // Convert string "info"/"debug" to spdlog enum
        spdlog::level::level_enum level = spdlog::level::info; 
        if(logLevel == "debug") level = spdlog::level::debug;
        if(logLevel == "warn")  level = spdlog::level::warn;
        if(logLevel == "error") level = spdlog::level::err;

        s_Logger->set_level(level);
        
        // Register it so spdlog knows about it globally
        spdlog::register_logger(s_Logger);
        
        // Auto-flush on errors so we don't lose logs if the app crashes
        s_Logger->flush_on(spdlog::level::err);

    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        std::cerr << "Falling back to Console-Only logging." << std::endl;
        s_Logger = createConsoleOnlyLogger();
    }
}

std::shared_ptr<spdlog::logger>& Logger::get() {
    // [NEW] Safety check: If get() is called before init(), create a temporary logger
    if (!s_Logger) {
        static auto fallback = createConsoleOnlyLogger();
        return fallback;
    }
    return s_Logger;
}