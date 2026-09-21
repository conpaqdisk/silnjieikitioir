#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

static const PluginDescriptor g_desc = {
    sizeof(PluginDescriptor),
    PLUGIN_API_VERSION_PACKED,
    "com.example.init_fail",
    "Init Fail Plugin",
    "1.0.0",
    "Example",
    PLUGIN_CAP_NONE,
};

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) { return &g_desc; }
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_initialize_v1(const PluginHostApi* h) {
    if (h) h->log(h->host_ctx, PLUGIN_LOG_WARN, "Init Fail Plugin: deliberately failing");
    set_last_error("simulated initialization failure");
    return PLUGIN_ERR_INTERNAL;
}
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_shutdown_v1(void) { return PLUGIN_OK; }
PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) { return get_last_error_internal(); }