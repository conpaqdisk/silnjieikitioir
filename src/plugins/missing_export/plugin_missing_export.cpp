#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

// Deliberately MISSING plugin_initialize_v1 to test MISSING_EXPORT detection.
static const PluginDescriptor g_desc = {
    sizeof(PluginDescriptor),
    PLUGIN_API_VERSION_PACKED,
    "com.example.missing_export",
    "Missing Export Plugin",
    "1.0.0",
    "Example",
    PLUGIN_CAP_NONE,
};

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) {
    return &g_desc;
}

// plugin_initialize_v1  -> intentionally not defined
// plugin_shutdown_v1    -> intentionally not defined
PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) {
    return get_last_error_internal();
}