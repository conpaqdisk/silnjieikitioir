#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "../src/host/plugin_loader.h"
#include "../src/host/logger.h"

static int g_pass = 0, g_fail = 0;

static void check(bool cond, const char* name) {
    if (cond) { std::printf("  [PASS] %s\n", name); g_pass++; }
    else      { std::printf("  [FAIL] %s\n", name); g_fail++; }
}

static std::wstring here() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s(buf, n);
    return s.substr(0, s.find_last_of(L"\\/"));
}

int wmain(int argc, wchar_t** argv) {
    g_log.set_min_level(PLUGIN_LOG_WARN);
    g_log.set_console(true);
    std::wstring dir = here() + L"\\test_plugins";

    std::printf("=== PluginLoader Automated Tests ===\n\n");

    // 1) Full batch (mixed success + failures)
    {
        PluginLoader loader;
        loader.scan_and_load(dir);

        int ok_count = 0, failed_count = 0;
        for (auto& r : loader.reports()) {
            if (r.status == LoadStatus::Ok) ok_count++; else failed_count++;
        }
        std::printf("Scenario 1: full batch (ok=%d, failed=%d)\n", ok_count, failed_count);
        check(ok_count >= 2, "at least success + dependent loaded");
        check(failed_count >= 4, "at least 4 failed as expected");
    }

    // 2) Double init must not be possible: loader is idempotent per scan
    {
        PluginLoader loader;
        loader.scan_and_load(dir);
        loader.scan_and_load(dir); // second scan should be a fresh load
        loader.shutdown_all();
        check(true, "double scan did not crash");
    }

    // 3) Reentrant shutdown: second call is safe
    {
        PluginLoader loader;
        loader.scan_and_load(dir);
        loader.shutdown_all();
        loader.shutdown_all(); // must not crash
        check(true, "double shutdown_all is safe");
    }

    // 4) tick_all on empty loader
    {
        PluginLoader loader;
        loader.tick_all(50);
        check(true, "tick_all on empty loader is safe");
    }

    std::printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}