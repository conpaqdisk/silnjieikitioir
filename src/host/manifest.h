// manifest.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "error_codes.h"

struct Manifest {
    bool ok = false;
    std::string plugin_id;
    std::string name;
    std::string version;
    uint32_t    required_api_version = 0;
    std::string architecture;                 // "x64" only
    std::vector<std::string> dependencies;    // plugin IDs
    std::vector<std::string> capabilities;    // strings
};

// Reads "<dll_path>.ini".  Returns:
//   Ok        -> parsed
//   ManifestMissing / ManifestInvalid on failure
LoadStatus manifest_load(const std::wstring& dll_path, Manifest& out, std::string& err);