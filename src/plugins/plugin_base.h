#pragma once
#include "plugin_api/plugin_api.h"
#include <string>

// Helper macro for export / declspec.
#ifdef PLUGIN_BUILD
#  define PLUGIN_EXPORT extern "C" __declspec(dllexport)
#else
#  define PLUGIN_EXPORT extern "C" __declspec(dllimport)
#endif

// Per-thread last-error storage.
inline thread_local std::string g_last_error;

static inline void set_last_error(const char* msg) {
    g_last_error = msg ? msg : "";
}
static inline const char* get_last_error_internal() {
    return g_last_error.c_str();
}