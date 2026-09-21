// pe_validator.h
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "error_codes.h"

struct PeInfo {
    bool            is_valid = false;
    bool            is_dll   = false;
    bool            is_x64   = false;
    uint32_t        machine  = 0;
    uint64_t        image_base = 0;
    std::string     sha256_hex;
    std::vector<std::string> imported_dlls; // lowercase
};

// Returns LoadStatus::Ok on success, otherwise the first failure reason.
LoadStatus pe_validate(const std::wstring& path, PeInfo& out, std::string& err);