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

ULONG_PTR map_image(msys_sandbox_compat::MapSection map, const wchar_t *path, ULONG_PTR zero) {
    HANDLE section = open_image_section(path);
    if (!section)
        return 0;
    PVOID base = nullptr;
    SIZE_T size = 0;
    LARGE_INTEGER offset{};
    auto status = map(section, GetCurrentProcess(), &base, zero, 0, &offset, &size, 2, 0, PAGE_READONLY);
    CloseHandle(section);
    if (status < 0 || !base)
        return 0;
    auto address = reinterpret_cast<ULONG_PTR>(base);
    UnmapViewOfFile(base);
    return address;
}

bool check_additional_views(msys_sandbox_compat::MapSection map, wchar_t (&path)[MAX_PATH]) {
    // The loaded wrapper occupies the preferred base of both files under test.
    if (reinterpret_cast<uintptr_t>(GetModuleHandleW(L"new-module.dll")) != 0x63000000000ULL)
        return false;
    auto name = wcsrchr(path, L'\\');
    if (!name)
        return false;
    auto select = [&](const wchar_t *filename) {
        return wcscpy_s(name + 1, MAX_PATH - (name + 1 - path), filename) == 0;
    };
    bool aslr_ok = select(L"late-aslr-module.dll") && map_image(map, path, 0);
    if (!aslr_ok) {
        constexpr char message[] = "LATE-DLL-DYNAMIC-BASE-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }

    bool retry_ok = select(L"late-conflict-module.dll") && map_image(map, path, 0);
    if (!retry_ok) {
        constexpr char message[] = "LATE-DLL-CONFLICT-RETRY-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }
    if (!select(L"late-low-module.dll"))
        return false;
    constexpr ULONG_PTR low_base = 0x34000000;
    const bool count_ok = map_image(map, path, 1) == low_base;
    // The sparse mask permits addresses through 0x3fffffff.
    const bool bitmap_ok = map_image(map, path, 0x20000000) == low_base;
    const auto constrained = map_image(map, path, 3);
    const bool constraint_ok = constrained && constrained < 0x20000000;
    if (!count_ok || !bitmap_ok || !constraint_ok) {
        constexpr char message[] = "LATE-DLL-ZEROBITS-FIXED-FAIL\n";
        write(2, message, sizeof(message) - 1);
    }
    return aslr_ok && retry_ok && count_ok && bitmap_ok && constraint_ok;
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
    const bool additional_ok = check_additional_views(map, path);
    return explicit_ok && constrained_ok && additional_ok;
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
