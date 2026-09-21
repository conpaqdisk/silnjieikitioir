#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include "logger.h"
#include "plugin_loader.h"
#include "safe_dll_dir.h"
#include "../plugin_api/plugin_api.h"

static std::wstring exe_dir() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s(buf, n);
    auto p = s.find_last_of(L"\\/");
    if (p != std::wstring::npos) s.resize(p);
    return s;
}

static std::wstring arg_value(int argc, wchar_t** argv, const wchar_t* name) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (_wcsicmp(argv[i], name) == 0) return argv[i + 1];
    }
    return {};
}

int wmain(int argc, wchar_t** argv) {
    // Safe DLL search
    if (!safe_dll::install()) {
        g_log.warn("HOST", "SetDefaultDllDirectories failed; using SetDllDirectory fallback");
    }

    // Optional log file / level
    auto logf = arg_value(argc, argv, L"--log");
    if (!logf.empty()) g_log.set_file(std::string(logf.begin(), logf.end()));

    if (arg_value(argc, argv, L"--quiet") == L"1") g_log.set_console(false);
    if (arg_value(argc, argv, L"--debug") == L"1") g_log.set_min_level(PLUGIN_LOG_DEBUG);

    std::wstring plugin_dir = arg_value(argc, argv, L"--plugins");
    if (plugin_dir.empty()) plugin_dir = exe_dir() + L"\\plugins";

    g_log.info("HOST", "Starting PluginLoader");
    g_log.info("HOST", "Plugin dir: " + std::string(plugin_dir.begin(), plugin_dir.end()));

    PluginLoader loader;
    loader.scan_and_load(plugin_dir);

    int loaded = 0, failed = 0;
    for (auto& r : loader.reports()) {
        if (r.status == LoadStatus::Ok) loaded++; else failed++;
    }
    g_log.info("HOST", "Loaded: " + std::to_string(loaded) +
                       "  Failed: " + std::to_string(failed));

    // Print a summary table
    std::fprintf(stdout, "\n=== LOAD SUMMARY ===\n");
    std::fprintf(stdout, "%-32s %-22s %s\n", "FILE", "STATUS", "DETAIL");
    for (auto& r : loader.reports()) {
        std::fprintf(stdout, "%-32s %-22s %s\n",
                     r.name.c_str(), load_status_str(r.status), r.detail.c_str());
    }
    std::fprintf(stdout, "\n");

    // Simple run loop: tick every 100 ms for 2 seconds, unless --run <seconds>
    uint32_t run_secs = 2;
    std::wstring rs = arg_value(argc, argv, L"--run");
    if (!rs.empty()) {
        try { run_secs = (uint32_t)std::stoul(std::string(rs.begin(), rs.end())); }
        catch (...) { run_secs = 2; }
    }

    auto start = ::GetTickCount64();
    uint64_t last = start;
    while ((::GetTickCount64() - start) < (uint64_t)run_secs * 1000ull) {
        ::Sleep(100);
        uint64_t now = ::GetTickCount64();
        uint32_t dt = (uint32_t)(now - last);
        last = now;
        loader.tick_all(dt);
    }

    g_log.info("HOST", "Shutting down");
    loader.shutdown_all();

    return failed == 0 ? 0 : 1;
}