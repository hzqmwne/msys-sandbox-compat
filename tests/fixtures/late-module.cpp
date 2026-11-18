#include "msys_sandbox_compat/native_api.h"
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

extern "C" __declspec(dllimport) int getpid();
extern "C" __declspec(dllimport) intptr_t write(int, const void *, size_t);

namespace {

HANDLE open_image_section(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return nullptr;
    HANDLE section = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(file);
    return section;
}

bool maps_without_preferred_base(msys_sandbox_compat::MapSection map, const wchar_t *path) {
    HANDLE section = open_image_section(path);
    if (!section)
        return false;
    PVOID base = nullptr;
    SIZE_T size = 0;
    auto status = map(section, GetCurrentProcess(), &base, 0, 0, nullptr, &size, 2, 0, PAGE_READONLY);
    CloseHandle(section);
    if (status < 0 || !base)
        return false;
    UnmapViewOfFile(base);
    return true;
}

bool check_unconstrained_views(msys_sandbox_compat::MapSection map, wchar_t (&path)[MAX_PATH]) {
    // The loaded wrapper occupies the preferred base of both files under test.
    if (reinterpret_cast<uintptr_t>(GetModuleHandleW(L"new-module.dll")) != 0x63000000000ULL)
        return false;
    auto name = wcsrchr(path, L'\\');
    if (!name || wcscpy_s(name + 1, MAX_PATH - (name + 1 - path), L"late-aslr-module.dll"))
        return false;
    bool aslr_ok = maps_without_preferred_base(map, path);
    if (!aslr_ok) {
        constexpr char message[] = "LATE-DLL-DYNAMIC-BASE-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }

    // From root\usr\bin\..., locate the sibling root-other\new-module.dll.
    for (int i = 0; i < 2; ++i) {
        *name = 0;
        name = wcsrchr(path, L'\\');
        if (!name)
            return false;
    }
    if (wcscpy_s(name, MAX_PATH - (name - path), L"-other\\new-module.dll"))
        return false;
    bool outside_ok = maps_without_preferred_base(map, path);
    if (!outside_ok) {
        constexpr char message[] = "LATE-DLL-OUTSIDE-ROOT-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }
    return aslr_ok && outside_ok;
}

bool check_mapping_requests() {
    auto map = reinterpret_cast<msys_sandbox_compat::MapSection>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));
    if (!map)
        return false;
    auto module = GetModuleHandleW(L"late-msys-helper.dll");
    wchar_t path[MAX_PATH];
    auto chars = module ? GetModuleFileNameW(module, path, MAX_PATH) : 0;
    if (!chars || chars >= MAX_PATH)
        return false;
    HANDLE section = open_image_section(path);
    if (!section)
        return false;

    // Pick a free, aligned range away from the helper's already loaded image.
    auto requested = VirtualAlloc(nullptr, 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
    bool explicit_ok = false;
    bool constrained_ok = false;
    if (requested && VirtualFree(requested, 0, MEM_RELEASE)) {
        PVOID base = requested;
        SIZE_T size = 0;
        if (map(section, GetCurrentProcess(), &base, 0, 0, nullptr, &size, 2, 0, PAGE_READONLY) >= 0) {
            explicit_ok = base == requested;
            if (base != module)
                UnmapViewOfFile(base);
        }
        base = nullptr;
        size = 0;
        if (map(section, GetCurrentProcess(), &base, 1, 0, nullptr, &size, 2, 0, PAGE_READONLY) >= 0) {
            constrained_ok = base && base != module;
            if (constrained_ok)
                UnmapViewOfFile(base);
        }
    }
    CloseHandle(section);
    if (!explicit_ok) {
        constexpr char message[] = "LATE-DLL-EXPLICIT-BASE-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }
    if (!constrained_ok) {
        constexpr char message[] = "LATE-DLL-ZEROBITS-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }
    const bool unconstrained_ok = check_unconstrained_views(map, path);
    return explicit_ok && constrained_ok && unconstrained_ok;
}

} // namespace

// Zero-argument Perl XSUB: leaving the Perl stack unchanged returns no values.
// This fixture needs no Perl headers or import library, and really calls MSYS.
extern "C" __declspec(dllexport) void late_dep_probe(void *, void *) {
    constexpr char success[] = "LATE-DLL-PASS\n";
    constexpr char failure[] = "LATE-DLL-FAIL\n";
    bool valid = getpid() > 0 && check_mapping_requests();
    write(1, valid ? success : failure, sizeof(success) - 1);
}
