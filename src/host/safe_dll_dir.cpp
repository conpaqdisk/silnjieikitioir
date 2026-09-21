// safe_dll_dir.cpp
#include "safe_dll_dir.h"
#include <windows.h>

namespace safe_dll {

bool install() {
    // Windows 8+ / KB2533623 API.
    // If not available, fall back to SetDllDirectoryW(L"") to strip CWD.
    HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;
    using PFN_SetDefaultDllDirectories = BOOL (WINAPI*)(DWORD);
    auto p = reinterpret_cast<PFN_SetDefaultDllDirectories>(
        ::GetProcAddress(k32, "SetDefaultDllDirectories"));
    if (p) {
        DWORD flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
        if (p(flags)) return true;
    }
    // Fallback: remove CWD
    return ::SetDllDirectoryW(L"") != FALSE;
}

void* load(const std::wstring& full_path, unsigned long* out_err) {
    if (out_err) *out_err = 0;

    wchar_t abs_buf[MAX_PATH]{};
    DWORD n = ::GetFullPathNameW(full_path.c_str(), MAX_PATH, abs_buf, nullptr);
    const wchar_t* path_to_load = (n > 0 && n < MAX_PATH) ? abs_buf : full_path.c_str();

    const DWORD flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    HMODULE h = ::LoadLibraryExW(path_to_load, nullptr, flags);
    if (!h && out_err) *out_err = ::GetLastError();
    return h;
}

} // namespace safe_dll