// safe_dll_dir.h
#pragma once
#include <string>

namespace safe_dll {
    // Restrict DLL search to: the DLL's own directory + System32 + Windows.
    // Removes CWD from the search order.  Returns true on success.
    bool install();

    // Load with the safe flags.  Uses LoadLibraryExW with
    // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS.
    void* load(const std::wstring& full_path, unsigned long* out_err);
}