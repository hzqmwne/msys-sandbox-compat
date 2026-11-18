#include "msys_sandbox_compat/native_api.h"
#include <stddef.h>
#include <stdint.h>

extern "C" __declspec(dllimport) int getpid();
extern "C" __declspec(dllimport) intptr_t write(int, const void *, size_t);

namespace {

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
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    HANDLE section = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(file);
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
    return explicit_ok && constrained_ok;
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
