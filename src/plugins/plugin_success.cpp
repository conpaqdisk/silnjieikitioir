#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

static const PluginDescriptor g_desc = {
    /*struct_size*/            sizeof(PluginDescriptor),
    /*required_api_version*/   PLUGIN_API_VERSION_PACKED,
    /*plugin_id*/              "com.example.success",
    /*plugin_name*/            "Success Plugin",
    /*plugin_version*/         "1.0.0",
    /*plugin_author*/          "Example",
    /*capabilities*/           PLUGIN_CAP_LOGGING | PLUGIN_CAP_TIMER,
};

static const PluginHostApi* g_host = nullptr;
static uint32_t g_ticks = 0;

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) {
    return &g_desc;
}

PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_initialize_v1(const PluginHostApi* host) {
    if (!host || host->struct_size < sizeof(PluginHostApi)) {
        set_last_error("invalid host api struct");
        return PLUGIN_ERR_INVALID_ARG;
    }
    g_host = host;
    g_host->log(g_host->host_ctx, PLUGIN_LOG_INFO, "Success Plugin initialized");
    return PLUGIN_OK;
}

PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_shutdown_v1(void) {
    if (!g_host) return PLUGIN_ERR_NOT_INITIALIZED;
    g_host->log(g_host->host_ctx, PLUGIN_LOG_INFO, "Success Plugin shutting down");
    g_host = nullptr;
    return PLUGIN_OK;
}

PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) {
    return get_last_error_internal();
}

PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_tick_v1(uint32_t /*dt_ms*/) {
    if (!g_host) return PLUGIN_ERR_NOT_INITIALIZED;
    if (++g_ticks == 5) {
        g_host->log(g_host->host_ctx, PLUGIN_LOG_DEBUG, "Success Plugin tick #5");
    }
    return PLUGIN_OK;
}