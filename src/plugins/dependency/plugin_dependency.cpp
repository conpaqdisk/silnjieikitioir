#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

static const PluginDescriptor g_desc = {
    sizeof(PluginDescriptor),
    PLUGIN_API_VERSION_PACKED,
    "com.example.dependent",
    "Dependent Plugin",
    "1.0.0",
    "Example",
    PLUGIN_CAP_LOGGING,
};

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) { return &g_desc; }

PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_initialize_v1(const PluginHostApi* h) {
    if (h) h->log(h->host_ctx, PLUGIN_LOG_INFO, "Dependent Plugin initialized (depends on success)");
    return PLUGIN_OK;
}
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_shutdown_v1(void) { return PLUGIN_OK; }
PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) { return ""; }