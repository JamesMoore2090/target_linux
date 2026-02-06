#include "Logger.hpp"
#include "QtLogSink.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <vector>

// 1. DEFINE the static member (Fixes LNK2019/LNK2001 for s_Logger)
std::shared_ptr<spdlog::logger> Logger::s_Logger;

// 2. DEFINE the static getter (Fixes LNK2001 for Logger::get)
std::shared_ptr<spdlog::logger>& Logger::get() {
    if (!s_Logger) {
        // Fallback to basic console logger if init hasn't been called
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        s_Logger = std::make_shared<spdlog::logger>("TARGEX", console_sink);
    }
    return s_Logger;
}

void Logger::init(const std::string& filePath, const std::string& logLevel) {
    try {
        std::vector<spdlog::sink_ptr> sinks;

        // Sink 1: Console (Colored)
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());

        // Sink 2: Rotating File
        sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(filePath, true));

        // Sink 3: Qt GUI Sink (Custom)
        sinks.push_back(std::make_shared<QtLogSink_mt>());

        s_Logger = std::make_shared<spdlog::logger>("TARGEX", sinks.begin(), sinks.end());
        
        // Set log level
        if (logLevel == "debug") s_Logger->set_level(spdlog::level::debug);
        else if (logLevel == "warn") s_Logger->set_level(spdlog::level::warn);
        else if (logLevel == "error") s_Logger->set_level(spdlog::level::err);
        else s_Logger->set_level(spdlog::level::info);

        s_Logger->flush_on(spdlog::level::info);
        spdlog::register_logger(s_Logger);

    } catch (const spdlog::spdlog_ex& ex) {
        printf("Log initialization failed: %s\n", ex.what());
    }
}

QtLogSignalProxy* Logger::getQtProxy() {
    if (!s_Logger) return nullptr;

    for (auto& sink : s_Logger->sinks()) {
        auto qt_sink = std::dynamic_pointer_cast<QtLogSink_mt>(sink);
        if (qt_sink) {
            return qt_sink->getProxy();
        }
    }
    return nullptr;
}

#include "moc_Logger.cpp"