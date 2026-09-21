// logger.h
#pragma once
#include <string>
#include <mutex>
#include <cstdio>
#include "../plugin_api/plugin_api.h"

class Logger {
public:
    Logger();
    ~Logger();

    void set_file(const std::string& path);      // optional
    void set_min_level(PluginLogLevel lvl) { min_level_ = lvl; }
    void set_console(bool on)              { console_ = on; }

    void log(PluginLogLevel lvl, const char* component, const std::string& msg);

    void debug(const char* c, const std::string& m) { log(PLUGIN_LOG_DEBUG, c, m); }
    void info (const char* c, const std::string& m) { log(PLUGIN_LOG_INFO,  c, m); }
    void warn (const char* c, const std::string& m) { log(PLUGIN_LOG_WARN,  c, m); }
    void error(const char* c, const std::string& m) { log(PLUGIN_LOG_ERROR, c, m); }

    // Thread-safe bridge for plugins.
    void log_from_plugin(void* /*host_ctx*/, PluginLogLevel lvl, const char* msg_utf8);

private:
    std::mutex      mtx_;
    FILE*           file_ = nullptr;
    bool            console_ = true;
    PluginLogLevel  min_level_ = PLUGIN_LOG_INFO;
};

extern Logger g_log;