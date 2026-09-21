#define PLUGIN_BUILD 1
#include "../common/plugin_base.h"

// Two DLLs, "circular_a" and "circular_b", each declares the other as dependency.
// For a minimal build we ship ONE DLL and two manifests referencing each other;
// the loader detects the cycle before loading.

static const PluginDescriptor g_desc = {
    sizeof(PluginDescriptor),
    PLUGIN_API_VERSION_PACKED,
    "com.example.circular_a",
    "Circular A",
    "1.0.0",
    "Example",
    PLUGIN_CAP_NONE,
};

PLUGIN_EXPORT const PluginDescriptor* PLUGIN_CALL plugin_get_descriptor_v1(void) { return &g_desc; }
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_initialize_v1(const PluginHostApi*) { return PLUGIN_OK; }
PLUGIN_EXPORT PluginResult PLUGIN_CALL plugin_shutdown_v1(void) { return PLUGIN_OK; }
PLUGIN_EXPORT const char* PLUGIN_CALL plugin_get_last_error_v1(void) { return ""; }