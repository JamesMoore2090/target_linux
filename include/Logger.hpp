#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <spdlog/spdlog.h>
#include <spdlog/sinks/base_sink.h>
#include <QObject>
#include <QString>
#include <memory>
#include <string>

// --- QT SIGNAL PROXY ---
// This class allows spdlog (C++) to communicate with the Qt GUI thread
class QtLogSignalProxy : public QObject {
    Q_OBJECT
public:
    explicit QtLogSignalProxy(QObject* parent = nullptr) : QObject(parent) {}

signals:
    void logReceived(QString message);
};

// --- LOGGER CLASS ---
class Logger {
public:
    static void init(const std::string& filePath, const std::string& logLevel);
    
    // Static getter for the spdlog instance
    static std::shared_ptr<spdlog::logger>& get();
    
    // Helper to find the Qt signal proxy for UI connection
    static QtLogSignalProxy* getQtProxy();

    // Template wrappers to simplify logging calls
    template<typename... Args>
    static void info(fmt::format_string<Args...> fmt, Args&&... args) {
        get()->info(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void warn(fmt::format_string<Args...> fmt, Args&&... args) {
        get()->warn(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void error(fmt::format_string<Args...> fmt, Args&&... args) {
        get()->error(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    static void debug(fmt::format_string<Args...> fmt, Args&&... args) {
        get()->debug(fmt, std::forward<Args>(args)...);
    }

private:
    // Static member declaration (defined in Logger.cpp)
    static std::shared_ptr<spdlog::logger> s_Logger;
};

#endif