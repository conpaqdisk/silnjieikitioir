// logger.cpp
#include "logger.h"
#include <windows.h>
#include <ctime>
#include <cstdarg>

Logger g_log;

Logger::Logger() = default;
Logger::~Logger() { if (file_) std::fclose(file_); }

void Logger::set_file(const std::string& path) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (file_) { std::fclose(file_); file_ = nullptr; }
    if (!path.empty()) {
        fopen_s(&file_, path.c_str(), "ab");
    }
}

void Logger::log(PluginLogLevel lvl, const char* component, const std::string& msg) {
    if (lvl < min_level_) return;
    std::lock_guard<std::mutex> lk(mtx_);

    SYSTEMTIME st; GetLocalTime(&st);
    char stamp[32];
    std::snprintf(stamp, sizeof(stamp), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    const char* lvl_str = "DEBUG";
    switch (lvl) {
    case PLUGIN_LOG_DEBUG: lvl_str = "DEBUG"; break;
    case PLUGIN_LOG_INFO:  lvl_str = "INFO "; break;
    case PLUGIN_LOG_WARN:  lvl_str = "WARN "; break;
    case PLUGIN_LOG_ERROR: lvl_str = "ERROR"; break;
    }
    if (console_) {
        std::fprintf(stdout, "[%s] [%s] [%s] %s\n", stamp, lvl_str, component, msg.c_str());
        std::fflush(stdout);
    }
    if (file_) {
        std::fprintf(file_,  "[%s] [%s] [%s] %s\n", stamp, lvl_str, component, msg.c_str());
        std::fflush(file_);
    }
}

void Logger::log_from_plugin(void*, PluginLogLevel lvl, const char* msg_utf8) {
    if (!msg_utf8) return;
    log(lvl, "PLUGIN", std::string(msg_utf8));
}