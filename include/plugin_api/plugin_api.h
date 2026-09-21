#pragma once
#include <stdint.h>
#include <stddef.h>
#include "plugin_version.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__WIN32__)
#  define PLUGIN_CALL __cdecl
#else
#  define PLUGIN_CALL
#endif

/* Export symbol names */
#define PLUGIN_EXPORT_DESCRIPTOR  "plugin_get_descriptor_v1"
#define PLUGIN_EXPORT_INITIALIZE  "plugin_initialize_v1"
#define PLUGIN_EXPORT_SHUTDOWN    "plugin_shutdown_v1"
#define PLUGIN_EXPORT_LAST_ERROR  "plugin_get_last_error_v1"
#define PLUGIN_EXPORT_TICK        "plugin_tick_v1"

/* Logging levels */
typedef enum PluginLogLevel {
    PLUGIN_LOG_DEBUG = 0,
    PLUGIN_LOG_INFO  = 1,
    PLUGIN_LOG_WARN  = 2,
    PLUGIN_LOG_ERROR = 3
} PluginLogLevel;

/* Plugin capabilities bitmask */
#define PLUGIN_CAP_NONE     0x00000000u
#define PLUGIN_CAP_LOGGING  0x00000001u
#define PLUGIN_CAP_TIMER    0x00000002u

/* Return / Status codes */
typedef enum PluginResult {
    PLUGIN_OK                   = 0,
    PLUGIN_ERR_INVALID_ARG      = 1,
    PLUGIN_ERR_NOT_INITIALIZED  = 2,
    PLUGIN_ERR_INTERNAL         = 3
} PluginResult;

/* Plugin descriptor (provided by plugin) */
#pragma pack(push, 8)
typedef struct PluginDescriptor {
    uint32_t    struct_size;
    uint32_t    required_api_version;
    const char* plugin_id;
    const char* plugin_name;
    const char* plugin_version;
    const char* plugin_author;
    uint32_t    capabilities;
} PluginDescriptor;

/* Host API (provided by host to plugin during initialization) */
typedef struct PluginHostApi {
    uint32_t struct_size;
    uint32_t api_version;
    void*    host_ctx;

    void     (PLUGIN_CALL *log)(void* host_ctx, PluginLogLevel level, const char* message);
    uint64_t (PLUGIN_CALL *get_tick_ms)(void* host_ctx);
    uint32_t (PLUGIN_CALL *get_host_api_version)(void* host_ctx);
} PluginHostApi;
#pragma pack(pop)

/* Function pointer typedefs */
typedef const PluginDescriptor* (PLUGIN_CALL *PFN_plugin_get_descriptor_v1)(void);
typedef PluginResult            (PLUGIN_CALL *PFN_plugin_initialize_v1)(const PluginHostApi* host);
typedef PluginResult            (PLUGIN_CALL *PFN_plugin_shutdown_v1)(void);
typedef const char*             (PLUGIN_CALL *PFN_plugin_get_last_error_v1)(void);
typedef PluginResult            (PLUGIN_CALL *PFN_plugin_tick_v1)(uint32_t dt_ms);

#ifdef __cplusplus
}
#endif
