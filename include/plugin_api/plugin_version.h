#pragma once
#include <stdint.h>

#define PLUGIN_VERSION_MAJOR 1
#define PLUGIN_VERSION_MINOR 0
#define PLUGIN_VERSION_PATCH 0

#define PLUGIN_VERSION_PACK(maj, min, pat) \
    ((uint32_t)(((uint32_t)(maj) << 16) | ((uint32_t)(min) << 8) | (uint32_t)(pat)))

#define PLUGIN_API_VERSION_PACKED \
    PLUGIN_VERSION_PACK(PLUGIN_VERSION_MAJOR, PLUGIN_VERSION_MINOR, PLUGIN_VERSION_PATCH)

/* Compatibility rule (v1 policy):
 *   - Major must match EXACTLY
 *   - Host minor must be >= plugin minor
 *   - Host patch is ignored
 *   Returns 1 if compatible, 0 otherwise. */
static inline int plugin_version_is_compatible(uint32_t host_ver, uint32_t plugin_req)
{
    uint32_t h_maj = (host_ver   >> 16) & 0xFFu;
    uint32_t h_min = (host_ver   >>  8) & 0xFFu;
    uint32_t p_maj = (plugin_req >> 16) & 0xFFu;
    uint32_t p_min = (plugin_req >>  8) & 0xFFu;
    if (h_maj != p_maj) return 0;
    if (h_min <  p_min) return 0;
    return 1;
}