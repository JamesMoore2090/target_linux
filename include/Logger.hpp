#pragma once
#include <spdlog/spdlog.h>
#include <string>
#include <memory>

class Logger {
public:
    // Initialize the logger (call this once in main)
    static void init(const std::string& filePath, const std::string& logLevel);

    // Get the underlying spdlog instance (if you need advanced features)
    static std::shared_ptr<spdlog::logger>& get();

    // Helper wrappers for cleaner syntax
    template<typename... Args>
    static void info(spdlog::format_string_t<Args...> fmt, Args &&... args) {
        get()->info(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void warn(spdlog::format_string_t<Args...> fmt, Args &&... args) {
        get()->warn(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void error(spdlog::format_string_t<Args...> fmt, Args &&... args) {
        get()->error(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void debug(spdlog::format_string_t<Args...> fmt, Args &&... args) {
        get()->debug(fmt, std::forward<Args>(args)...);
    }

private:
    static std::shared_ptr<spdlog::logger> s_Logger;
};