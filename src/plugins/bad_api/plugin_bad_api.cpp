#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

// Declares a future API version (major 99) that the current host must reject.
static const PluginDescriptor g_desc = {
    sizeof(PluginDescriptor),
    PLUGIN_VERSION_PACK(99, 0, 0),
    "com.example.bad_api",
    "Bad API Plugin",
    "1.0.0",
    "Example",
    PLUGIN_CAP_NONE,
};

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) { return &g_desc; }
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_initialize_v1(const PluginHostApi*) { return PLUGIN_OK; }
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_shutdown_v1(void) { return PLUGIN_OK; }
PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) { return ""; }