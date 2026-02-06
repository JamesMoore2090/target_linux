#pragma once
#include <QObject>
#include <spdlog/sinks/base_sink.h>
#include <mutex>

// We need a helper QObject because spdlog sinks themselves cannot have signals
// class QtLogSignalProxy : public QObject {
//     Q_OBJECT
// signals:
//     void logReceived(QString message);
// };

template<typename Mutex>
class QtLogSink : public spdlog::sinks::base_sink<Mutex> {
public:
    QtLogSink() : proxy(new QtLogSignalProxy()) {}
    
    // This is where you connect the UI to the logger
    QtLogSignalProxy* getProxy() { return proxy.get(); }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        spdlog::memory_buf_t formatted;
        spdlog::sinks::base_sink<Mutex>::formatter_->format(msg, formatted);
        
        // Emit the signal to the UI thread
        QString text = QString::fromStdString(fmt::to_string(formatted));
        emit proxy->logReceived(text);
    }

    void flush_() override {}

private:
    std::unique_ptr<QtLogSignalProxy> proxy;
};

#include <spdlog/details/null_mutex.h>
using QtLogSink_mt = QtLogSink<std::mutex>;