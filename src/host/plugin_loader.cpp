// plugin_loader.cpp
#include "plugin_loader.h"
#include "logger.h"
#include "safe_dll_dir.h"
#include "plugin_api/plugin_version.h"
#include "dep_graph.h"
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

namespace {

std::string w2u8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

// Build a PluginHostApi for a plugin.  host_ctx = this loader.
void host_log_bridge(void*, PluginLogLevel lvl, const char* msg) {
    g_log.log_from_plugin(nullptr, lvl, msg ? msg : "");
}
uint64_t host_tick_bridge(void*) {
    return (uint64_t)::GetTickCount64();
}
uint32_t host_api_ver_bridge(void*) {
    return PLUGIN_API_VERSION_PACKED;
}

PluginResult safe_call_init(PFN_plugin_initialize_v1 fn, const PluginHostApi* api) {
    __try {
        return fn(api);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return PLUGIN_ERR_INTERNAL;
    }
}

const char* safe_call_last_error(PFN_plugin_get_last_error_v1 fn) {
    __try {
        return fn ? fn() : "";
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "";
    }
}

const PluginDescriptor* safe_call_descriptor(PFN_plugin_get_descriptor_v1 fn) {
    __try {
        return fn ? fn() : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

bool safe_call_tick(PFN_plugin_tick_v1 fn, uint32_t dt_ms) {
    __try {
        fn(dt_ms);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

PluginResult safe_call_shutdown(PFN_plugin_shutdown_v1 fn) {
    __try {
        return fn ? fn() : PLUGIN_ERR_INTERNAL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return PLUGIN_ERR_INTERNAL;
    }
}

} // namespace

PluginLoader::PluginLoader() {
    host_api_.struct_size = sizeof(PluginHostApi);
    host_api_.api_version = PLUGIN_API_VERSION_PACKED;
    host_api_.host_ctx    = this;
    host_api_.log         = &host_log_bridge;
    host_api_.get_tick_ms = &host_tick_bridge;
    host_api_.get_host_api_version = &host_api_ver_bridge;
}
PluginLoader::~PluginLoader() {
    shutdown_all();
}

void PluginLoader::scan_and_load(const std::wstring& dir) {
    shutdown_all();
    std::lock_guard<std::mutex> lk(mtx_);
    reports_.clear();

    wchar_t abs_dir_buf[MAX_PATH]{};
    DWORD n = ::GetFullPathNameW(dir.c_str(), MAX_PATH, abs_dir_buf, nullptr);
    std::wstring clean_dir = (n > 0 && n < MAX_PATH) ? abs_dir_buf : dir;

    std::wstring pattern = clean_dir + L"\\*.dll";
    WIN32_FIND_DATAW fd{};
    HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        LoadReport r{};
        r.path = clean_dir;
        r.status = LoadStatus::FileNotFound;
        r.detail = "no plugin directory or no DLLs";
        r.win_err = ::GetLastError();
        reports_.push_back(r);
        g_log.warn("LOADER", r.detail);
        return;
    }

    std::vector<Candidate> candidates;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        Candidate c{};
        c.path = clean_dir + L"\\" + fd.cFileName;
        c.file_name_utf8 = w2u8(fd.cFileName);

        // 1) Manifest
        std::string err;
        LoadStatus s = manifest_load(c.path, c.manifest, err);
        if (s != LoadStatus::Ok) {
            c.pre_status = s; c.pre_detail = err;
            candidates.push_back(std::move(c));
            continue;
        }

        // 2) PE
        s = pe_validate(c.path, c.pe, err);
        if (s != LoadStatus::Ok) {
            c.pre_status = s; c.pre_detail = err;
            candidates.push_back(std::move(c));
            continue;
        }

        // 3) API version gate (manifest-required vs host)
        if (!plugin_version_is_compatible(PLUGIN_API_VERSION_PACKED, c.manifest.required_api_version)) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                "required 0x%08X vs host 0x%08X",
                c.manifest.required_api_version, PLUGIN_API_VERSION_PACKED);
            c.pre_status = LoadStatus::ApiVersionMismatch;
            c.pre_detail = buf;
            candidates.push_back(std::move(c));
            continue;
        }

        // 4) Manifest vs SHA / architecture cross-check
        if (c.manifest.architecture != "x64" || !c.pe.is_x64) {
            c.pre_status = LoadStatus::WrongArchitecture;
            c.pre_detail = "manifest or PE is not x64";
            candidates.push_back(std::move(c));
            continue;
        }

        candidates.push_back(std::move(c));
    } while (::FindNextFileW(h, &fd));
    ::FindClose(h);

    // 5) Duplicate plugin_id detection
    {
        std::unordered_set<std::string> seen;
        for (auto& c : candidates) {
            if (c.pre_status != LoadStatus::Ok) continue;
            if (c.manifest.plugin_id.empty()) continue;
            if (!seen.insert(c.manifest.plugin_id).second) {
                c.pre_status = LoadStatus::DuplicatePluginId;
                c.pre_detail = "plugin_id duplicated: " + c.manifest.plugin_id;
            }
        }
    }

    // 6) Dependency graph
    DepGraph g;
    std::unordered_map<std::string, size_t> by_id;
    for (size_t i = 0; i < candidates.size(); ++i) {
        auto& c = candidates[i];
        if (c.pre_status != LoadStatus::Ok) continue;
        g.add_node(c.manifest.plugin_id);
        by_id[c.manifest.plugin_id] = i;
    }
    for (auto& c : candidates) {
        if (c.pre_status != LoadStatus::Ok) continue;
        for (auto& d : c.manifest.dependencies) {
            if (!by_id.count(d)) {
                c.pre_status = LoadStatus::DependencyMissing;
                c.pre_detail = "missing dependency: " + d;
                continue;
            }
            g.add_edge(c.manifest.plugin_id, d);
        }
    }

    std::vector<std::string> order, cycle;
    if (!g.topo(order, cycle)) {
        std::unordered_set<std::string> cycle_set(cycle.begin(), cycle.end());
        std::string msg = "dependency cycle: ";
        for (size_t i = 0; i < cycle.size(); ++i) { if (i) msg += ", "; msg += cycle[i]; }
        for (auto& c : candidates) {
            if (c.pre_status == LoadStatus::Ok && cycle_set.count(c.manifest.plugin_id)) {
                c.pre_status = LoadStatus::DependencyCycle;
                c.pre_detail = msg;
            }
        }
    }

    // 7) Load in topological order
    std::vector<std::wstring> deferred_unload;
    for (auto& id : order) {
        auto idx = by_id[id];
        Candidate& c = candidates[idx];

        LoadedPlugin lp{};
        std::string detail;
        unsigned long we = 0;
        LoadStatus s = load_one(c.path, lp, detail, we);
        if (s != LoadStatus::Ok) {
            LoadReport r{};
            r.path = c.path; r.name = c.file_name_utf8;
            r.status = s; r.detail = detail; r.win_err = we;
            reports_.push_back(std::move(r));
            g_log.error("LOADER", std::string("load failed: ") + load_status_str(s) + " (" + detail + ")");
            continue;
        }

        // 8) Initialize with SEH guard
        PluginResult pr = safe_call_init(lp.p_initialize, &host_api_);

        if (pr != PLUGIN_OK) {
            const char* perr = safe_call_last_error(lp.p_get_last_error);

            LoadReport r{};
            r.path = c.path; r.name = c.file_name_utf8;
            r.status = LoadStatus::InitFailed;
            r.detail = std::string("plugin_initialize_v1 returned ") +
                       std::to_string((int)pr) + ": " + (perr ? perr : "");
            g_log.error("LOADER", r.detail);
            reports_.push_back(std::move(r));

            // Safe unload
            ::FreeLibrary(lp.module);
            continue;
        }

        lp.initialized = true;
        loaded_.push_back(std::move(lp));
        reports_.push_back(LoadReport{c.path, c.file_name_utf8, LoadStatus::Ok, "loaded", 0});

        char b[256];
        std::snprintf(b, sizeof(b), "loaded '%s' v%s (id=%s)",
                      loaded_.back().name.c_str(), loaded_.back().version.c_str(),
                      loaded_.back().manifest_id.c_str());
        g_log.info("LOADER", b);
    }

    // Record pre-load failures
    for (auto& c : candidates) {
        if (c.pre_status == LoadStatus::Ok) continue;
        reports_.push_back(LoadReport{c.path, c.file_name_utf8, c.pre_status, c.pre_detail, c.pre_win});
        g_log.error("LOADER", std::string(c.file_name_utf8) + " -> " +
                              load_status_str(c.pre_status) + " (" + c.pre_detail + ")");
    }
}

LoadStatus PluginLoader::load_one(const std::wstring& path, LoadedPlugin& out,
                                  std::string& detail, unsigned long& win_err) {
    detail.clear(); win_err = 0;

    HMODULE h = (HMODULE)safe_dll::load(path, &win_err);
    if (!h) {
        detail = "LoadLibraryExW failed, GetLastError=" + std::to_string(win_err);
        if (win_err == ERROR_MOD_NOT_FOUND) return LoadStatus::DependencyMissing;
        if (win_err == ERROR_ACCESS_DENIED)  return LoadStatus::FileAccessDenied;
        return LoadStatus::UnknownError;
    }

    auto p_get_desc = (PFN_plugin_get_descriptor_v1)::GetProcAddress(h, PLUGIN_EXPORT_DESCRIPTOR);
    auto p_init     = (PFN_plugin_initialize_v1)    ::GetProcAddress(h, PLUGIN_EXPORT_INITIALIZE);
    auto p_shut     = (PFN_plugin_shutdown_v1)      ::GetProcAddress(h, PLUGIN_EXPORT_SHUTDOWN);
    auto p_last     = (PFN_plugin_get_last_error_v1)::GetProcAddress(h, PLUGIN_EXPORT_LAST_ERROR);
    auto p_tick     = (PFN_plugin_tick_v1)          ::GetProcAddress(h, PLUGIN_EXPORT_TICK);

    if (!p_get_desc || !p_init || !p_shut || !p_last) {
        detail = "missing required export(s)";
        ::FreeLibrary(h);
        return LoadStatus::MissingExport;
    }

    // Descriptor sanity
    const PluginDescriptor* d = safe_call_descriptor(p_get_desc);
    if (!d || d->struct_size < sizeof(PluginDescriptor) - sizeof(uint32_t) ||
        !d->plugin_id || !d->plugin_name || !d->plugin_version) {
        detail = "invalid descriptor returned";
        ::FreeLibrary(h);
        return LoadStatus::InvalidPe;
    }
    if (!plugin_version_is_compatible(PLUGIN_API_VERSION_PACKED, d->required_api_version)) {
        char b[128];
        std::snprintf(b, sizeof(b),
            "plugin requires 0x%08X, host 0x%08X",
            d->required_api_version, PLUGIN_API_VERSION_PACKED);
        detail = b;
        ::FreeLibrary(h);
        return LoadStatus::ApiVersionMismatch;
    }

    out.module          = h;
    out.p_get_descriptor = p_get_desc;
    out.p_initialize     = p_init;
    out.p_shutdown       = p_shut;
    out.p_get_last_error = p_last;
    out.p_tick           = p_tick;
    out.manifest_id      = d->plugin_id;
    out.name             = d->plugin_name;
    out.version          = d->plugin_version;
    out.required_api     = d->required_api_version;
    out.capabilities     = d->capabilities;
    out.dll_path_w_utf8  = w2u8(path);
    return LoadStatus::Ok;
}

void PluginLoader::tick_all(uint32_t dt_ms) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& p : loaded_) {
        if (!p.initialized || !p.p_tick) continue;
        if (!safe_call_tick(p.p_tick, dt_ms)) {
            g_log.error("LOADER", "plugin_tick_v1 raised an exception in: " + p.name);
        }
    }
}

void PluginLoader::shutdown_all() {
    std::lock_guard<std::mutex> lk(mtx_);
    // Reverse load order
    for (auto it = loaded_.rbegin(); it != loaded_.rend(); ++it) {
        if (!it->initialized) continue;
        PluginResult pr = safe_call_shutdown(it->p_shutdown);

        if (pr != PLUGIN_OK) {
            g_log.warn("LOADER", "shutdown returned error (" + std::to_string((int)pr) + ") in: " + it->name);
            reports_.push_back(LoadReport{std::wstring(), it->name,
                                          LoadStatus::ShutdownFailed,
                                          "shutdown returned " + std::to_string((int)pr), 0});
        }

        if (it->module) {
            if (!::FreeLibrary(it->module)) {
                reports_.push_back(LoadReport{std::wstring(), it->name,
                                              LoadStatus::UnloadFailed,
                                              "FreeLibrary failed", ::GetLastError()});
            }
        }
        it->initialized = false;
        it->module = nullptr;
    }
    loaded_.clear();
}