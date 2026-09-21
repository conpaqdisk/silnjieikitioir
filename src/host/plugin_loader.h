// plugin_loader.h
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include "error_codes.h"
#include "manifest.h"
#include "pe_validator.h"
#include "../plugin_api/plugin_api.h"

struct LoadedPlugin {
    std::string  dll_path_w_utf8;       // for diagnostics
    std::string  manifest_id;
    std::string  name;
    std::string  version;
    uint32_t     required_api = 0;
    uint32_t     capabilities = 0;

    HMODULE      module  = nullptr;
    PFN_plugin_get_descriptor_v1  p_get_descriptor = nullptr;
    PFN_plugin_initialize_v1      p_initialize     = nullptr;
    PFN_plugin_shutdown_v1        p_shutdown       = nullptr;
    PFN_plugin_get_last_error_v1  p_get_last_error = nullptr;
    PFN_plugin_tick_v1            p_tick           = nullptr; // optional

    bool         initialized = false;
};

struct LoadReport {
    std::wstring path;
    std::string  name;          // file name utf8
    LoadStatus   status = LoadStatus::UnknownError;
    std::string  detail;        // human message
    unsigned long win_err = 0;  // GetLastError if relevant
};

// Thread-safe: init/shutdown must not be called concurrently.
class PluginLoader {
public:
    PluginLoader();
    ~PluginLoader();

    // Scan a directory for *.dll.  Loads compatible plugins in dependency order.
    // Plugins with errors do not abort the batch.
    void scan_and_load(const std::wstring& directory);

    // Call tick on each loaded plugin that exports tick.  dt in ms.
    void tick_all(uint32_t dt_ms);

    // Shutdown+unload all plugins in reverse load order.
    void shutdown_all();

    const std::vector<LoadedPlugin>& plugins() const { return loaded_; }
    const std::vector<LoadReport>&  reports() const { return reports_;  }

private:
    LoadStatus load_one(const std::wstring& path,
                        LoadedPlugin& out,
                        std::string& detail,
                        unsigned long& win_err);

    // Two-phase load: candidates first, then graph sort.
    struct Candidate {
        std::wstring path;
        std::string  file_name_utf8;
        Manifest     manifest;
        PeInfo       pe;
        LoadedPlugin proto;   // not yet initialized
        LoadStatus   pre_status = LoadStatus::Ok;
        std::string  pre_detail;
        unsigned long pre_win  = 0;
    };

    std::mutex                         mtx_;
    std::vector<LoadedPlugin>          loaded_;
    std::vector<LoadReport>            reports_;
    std::vector<HMODULE>               pending_unload_; // loaded but not initialized
    PluginHostApi                      host_api_{};
};