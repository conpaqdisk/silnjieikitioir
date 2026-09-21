// manifest.cpp
#include "manifest.h"
#include "plugin_api/plugin_version.h"
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace {

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else if (c != ' ' && c != '\t') {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string get_ini(const std::wstring& path, const wchar_t* section, const wchar_t* key) {
    wchar_t buf[1024]{};
    ::GetPrivateProfileStringW(section, key, L"", buf, (DWORD)std::size(buf), path.c_str());
    return narrow(buf);
}

uint32_t parse_version(const std::string& s, bool& valid) {
    valid = false;
    unsigned a=0,b=0,c=0;
    if (std::sscanf(s.c_str(), "%u.%u.%u", &a, &b, &c) == 3) {
        if (a > 0xFFFF || b > 0xFFFF || c > 0xFFFF) return 0;
        valid = true;
        return PLUGIN_VERSION_PACK(a,b,c);
    }
    return 0;
}

} // namespace

LoadStatus manifest_load(const std::wstring& dll_path, Manifest& out, std::string& err) {
    out = {}; err.clear();
    std::wstring ini = dll_path + L".ini";
    DWORD attrs = ::GetFileAttributesW(ini.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        err = "manifest file missing: " + narrow(ini);
        return LoadStatus::ManifestMissing;
    }

    out.plugin_id = get_ini(ini, L"plugin", L"id");
    out.name      = get_ini(ini, L"plugin", L"name");
    out.version   = get_ini(ini, L"plugin", L"version");
    std::string v = get_ini(ini, L"plugin", L"api_version");
    out.architecture = get_ini(ini, L"plugin", L"architecture");
    std::string deps = get_ini(ini, L"plugin", L"dependencies");
    std::string caps = get_ini(ini, L"plugin", L"capabilities");

    if (out.plugin_id.empty() || out.name.empty() || out.version.empty() ||
        v.empty() || out.architecture.empty()) {
        err = "manifest missing required fields";
        return LoadStatus::ManifestInvalid;
    }
    bool okv = false;
    out.required_api_version = parse_version(v, okv);
    if (!okv) { err = "manifest api_version malformed: " + v; return LoadStatus::ManifestInvalid; }
    if (out.architecture != "x64") {
        err = "manifest architecture not x64: " + out.architecture;
        return LoadStatus::ManifestInvalid;
    }
    bool okp = false;
    (void)parse_version(out.version, okp);
    if (!okp) { err = "manifest plugin version malformed: " + out.version; return LoadStatus::ManifestInvalid; }

    out.dependencies = split(deps, ';');
    out.capabilities = split(caps, ';');
    out.ok = true;
    return LoadStatus::Ok;
}