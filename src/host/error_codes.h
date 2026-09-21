#pragma once
#include <stdint.h>

enum class LoadStatus : uint32_t {
    Ok                    = 0,
    FileNotFound          = 1,
    FileAccessDenied      = 2,
    NotADll               = 3,
    WrongArchitecture     = 4,
    InvalidPe             = 5,
    MissingExport         = 6,
    ApiVersionMismatch    = 7,
    ManifestMissing       = 8,
    ManifestInvalid       = 9,
    ManifestMismatch      = 10,
    DependencyMissing     = 11,
    DependencyCycle       = 12,
    InitFailed            = 13,
    AlreadyLoaded         = 14,
    ShutdownFailed        = 15,
    UnloadFailed          = 16,
    DuplicatePluginId     = 17,
    UnknownError          = 18
};

inline const char* load_status_str(LoadStatus s) {
    switch (s) {
    case LoadStatus::Ok:                 return "OK";
    case LoadStatus::FileNotFound:       return "FILE_NOT_FOUND";
    case LoadStatus::FileAccessDenied:   return "FILE_ACCESS_DENIED";
    case LoadStatus::NotADll:            return "NOT_A_DLL";
    case LoadStatus::WrongArchitecture:  return "WRONG_ARCHITECTURE";
    case LoadStatus::InvalidPe:          return "INVALID_PE";
    case LoadStatus::MissingExport:      return "MISSING_EXPORT";
    case LoadStatus::ApiVersionMismatch: return "API_VERSION_MISMATCH";
    case LoadStatus::ManifestMissing:    return "MANIFEST_MISSING";
    case LoadStatus::ManifestInvalid:    return "MANIFEST_INVALID";
    case LoadStatus::ManifestMismatch:   return "MANIFEST_MISMATCH";
    case LoadStatus::DependencyMissing:  return "DEPENDENCY_MISSING";
    case LoadStatus::DependencyCycle:    return "DEPENDENCY_CYCLE";
    case LoadStatus::InitFailed:         return "INIT_FAILED";
    case LoadStatus::AlreadyLoaded:      return "ALREADY_LOADED";
    case LoadStatus::ShutdownFailed:     return "SHUTDOWN_FAILED";
    case LoadStatus::UnloadFailed:       return "UNLOAD_FAILED";
    case LoadStatus::DuplicatePluginId:  return "DUPLICATE_PLUGIN_ID";
    case LoadStatus::UnknownError:       return "UNKNOWN_ERROR";
    }
    return "?";
}