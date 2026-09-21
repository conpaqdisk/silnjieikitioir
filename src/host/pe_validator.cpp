// pe_validator.cpp
#include "pe_validator.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <fstream>
#include <cstdint>
#include <algorithm>

namespace {

struct FileBlob {
    std::vector<uint8_t> data;
    bool ok = false;
};

FileBlob read_all(const std::wstring& p) {
    FileBlob b;
    HANDLE h = ::CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return b;
    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 30)) {
        ::CloseHandle(h); return b;
    }
    b.data.resize((size_t)sz.QuadPart);
    DWORD read = 0;
    BOOL ok = ::ReadFile(h, b.data.data(), (DWORD)b.data.size(), &read, nullptr);
    ::CloseHandle(h);
    b.ok = ok && read == b.data.size();
    return b;
}

bool sha256_hex(const std::vector<uint8_t>& d, std::string& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(alg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    uint8_t hash[32]{};
    bool ok = (BCryptHashData(hHash, (PUCHAR)d.data(), (ULONG)d.size(), 0) == 0 &&
               BCryptFinishHash(hHash, hash, 32, 0) == 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(alg, 0);

    if (!ok) return false;

    static const char* hx = "0123456789abcdef";
    out.clear(); out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(hx[hash[i] >> 4]);
        out.push_back(hx[hash[i] & 15]);
    }
    return true;
}

const IMAGE_SECTION_HEADER* find_section(const IMAGE_NT_HEADERS32* nt, const char* name) {
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, name, 8) == 0) return sec;
    }
    return nullptr;
}

} // namespace

LoadStatus pe_validate(const std::wstring& path, PeInfo& out, std::string& err) {
    out = {};
    err.clear();

    // File exists / readable?
    DWORD attrs = ::GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD e = ::GetLastError();
        err = "GetFileAttributesW failed: " + std::to_string(e);
        return (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
                   ? LoadStatus::FileNotFound : LoadStatus::FileAccessDenied;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        err = "path is a directory";
        return LoadStatus::InvalidPe;
    }

    FileBlob blob = read_all(path);
    if (!blob.ok) {
        err = "file read failed: " + std::to_string(::GetLastError());
        return LoadStatus::FileAccessDenied;
    }
    if (blob.data.size() < sizeof(IMAGE_DOS_HEADER)) {
        err = "file smaller than DOS header";
        return LoadStatus::InvalidPe;
    }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(blob.data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        err = "bad DOS signature";
        return LoadStatus::InvalidPe;
    }
    if (dos->e_lfanew <= 0 ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > blob.data.size()) {
        err = "invalid e_lfanew";
        return LoadStatus::InvalidPe;
    }
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(blob.data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        err = "bad NT signature";
        return LoadStatus::InvalidPe;
    }

    out.machine = nt->FileHeader.Machine;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        err = "not x64 (machine=0x" + std::to_string(nt->FileHeader.Machine) + ")";
        out.is_valid = true;
        out.is_x64 = false;
        return LoadStatus::WrongArchitecture;
    }
    out.is_x64 = true;

    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        err = "IMAGE_FILE_DLL not set";
        out.is_valid = true;
        return LoadStatus::NotADll;
    }
    out.is_dll = true;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        err = "optional header is not PE32+";
        return LoadStatus::WrongArchitecture;
    }

    auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt);
    out.image_base = nt64->OptionalHeader.ImageBase;

    // SHA256
    if (!sha256_hex(blob.data, out.sha256_hex)) {
        err = "sha256 compute failed";
        return LoadStatus::UnknownError;
    }

    // Imports (only for validation; missing imports are a soft fail here,
    // we let the OS confirm at load time as a second line of defense).
    const IMAGE_DATA_DIRECTORY& imp_dir =
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress && imp_dir.Size) {
        const IMAGE_SECTION_HEADER* sec = nullptr;
        {
            auto s = IMAGE_FIRST_SECTION(nt64);
            for (unsigned i = 0; i < nt64->FileHeader.NumberOfSections; ++i, ++s) {
                if (imp_dir.VirtualAddress >= s->VirtualAddress &&
                    imp_dir.VirtualAddress < s->VirtualAddress + s->Misc.VirtualSize) {
                    sec = s; break;
                }
            }
        }
        if (sec) {
            size_t off = sec->PointerToRawData + (imp_dir.VirtualAddress - sec->VirtualAddress);
            for (size_t i = 0; i < 64 && off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= blob.data.size(); ++i) {
                auto d = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(blob.data.data() + off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
                if (!d->Name) break;
                const IMAGE_SECTION_HEADER* ns = nullptr;
                {
                    auto s = IMAGE_FIRST_SECTION(nt64);
                    for (unsigned k = 0; k < nt64->FileHeader.NumberOfSections; ++k, ++s) {
                        if (d->Name >= s->VirtualAddress &&
                            d->Name < s->VirtualAddress + s->Misc.VirtualSize) { ns = s; break; }
                    }
                }
                if (!ns) continue;
                size_t noff = ns->PointerToRawData + (d->Name - ns->VirtualAddress);
                if (noff >= blob.data.size()) continue;
                const char* name = reinterpret_cast<const char*>(blob.data.data() + noff);
                size_t maxlen = blob.data.size() - noff;
                std::string s2(name, strnlen(name, maxlen));
                std::transform(s2.begin(), s2.end(), s2.begin(),
                               [](unsigned char c){ return (char)std::tolower(c); });
                out.imported_dlls.push_back(std::move(s2));
            }
        }
    }

    out.is_valid = true;
    return LoadStatus::Ok;
}