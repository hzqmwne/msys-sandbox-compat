#include "host.h"
#include <cstdio>
#include <stdexcept>

namespace msys_compat {
void check(bool success, const char *operation) {
    if (!success) {
        fprintf(stderr, "[error] %s: Win32 %lu\n", operation, GetLastError());
        throw std::runtime_error(operation);
    }
}
void check_nt(NTSTATUS status, const char *operation) {
    if (status < 0) {
        fprintf(stderr, "[error] %s: NTSTATUS %08lx\n", operation, static_cast<ULONG>(status));
        throw std::runtime_error(operation);
    }
}
std::wstring file_path(HANDLE file) {
    wchar_t buffer[32768];
    auto size = GetFinalPathNameByHandleW(file, buffer, _countof(buffer), VOLUME_NAME_NT);
    check(size && size < _countof(buffer), "GetFinalPathNameByHandleW");
    return {buffer, size};
}
NativeApi resolve_api() {
    NativeApi api{};
    auto module = GetModuleHandleW(L"ntdll.dll");
#define RESOLVE(field, name)                                                                       \
    api.field = reinterpret_cast<decltype(api.field)>(GetProcAddress(module, name));               \
    check(api.field != nullptr, name)
    RESOLVE(allocate, "NtAllocateVirtualMemory");
    RESOLVE(free, "NtFreeVirtualMemory");
    RESOLVE(read, "NtReadVirtualMemory");
    RESOLVE(write, "NtWriteVirtualMemory");
    RESOLVE(protect, "NtProtectVirtualMemory");
    RESOLVE(query_memory, "NtQueryVirtualMemory");
    RESOLVE(query_process, "NtQueryInformationProcess");
    RESOLVE(get_context, "NtGetContextThread");
    RESOLVE(set_context, "NtSetContextThread");
    RESOLVE(resume, "NtResumeThread");
    RESOLVE(terminate, "NtTerminateProcess");
    RESOLVE(create_section, "NtCreateSection");
    RESOLVE(map_section, "NtMapViewOfSection");
    RESOLVE(unmap_section, "NtUnmapViewOfSection");
    RESOLVE(query_section, "NtQuerySection");
    RESOLVE(query_object, "NtQueryObject");
    RESOLVE(open_file, "NtOpenFile");
    RESOLVE(write_file, "NtWriteFile");
    RESOLVE(read_file, "NtReadFile");
    RESOLVE(flush_code, "NtFlushInstructionCache");
    RESOLVE(close, "NtClose");
    RESOLVE(set_security, "NtSetSecurityObject");
    RESOLVE(query_token, "NtQueryInformationToken");
    RESOLVE(open_token, "NtOpenProcessToken");
    RESOLVE(set_token, "NtSetInformationToken");
    RESOLVE(create_process, "NtCreateUserProcess");
    RESOLVE(create_directory, "NtCreateDirectoryObject");
    RESOLVE(create_mutant, "NtCreateMutant");
    RESOLVE(create_link, "NtCreateSymbolicLinkObject");
    RESOLVE(create_pipe, "NtCreateNamedPipeFile");
    RESOLVE(add_function_table, "RtlAddFunctionTable");
#undef RESOLVE
    return api;
}
namespace {
std::wstring native_directory(const std::filesystem::path &path) {
    HANDLE directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    check(directory != INVALID_HANDLE_VALUE, "open dependency search directory");
    auto result = file_path(directory) + L"\\";
    CloseHandle(directory);
    check(result.size() < image_path_chars, "dependency directory capacity");
    return result;
}
} // namespace

void configure_runtime_paths(const std::filesystem::path &runtime, AgentState &state) {
    // --runtime supplies a dependency-search directory, not a file identity.
    auto directory_path = native_directory(runtime.parent_path());
    memcpy(state.runtime.directory, directory_path.c_str(), (directory_path.size() + 1) * 2);
    wchar_t directory[image_path_chars];
    auto chars = GetSystemDirectoryW(directory, _countof(directory));
    check(chars && chars < _countof(directory), "system directory");
    auto system_path = native_directory(directory);
    memcpy(state.runtime.system_directory, system_path.c_str(), (system_path.size() + 1) * 2);
}
} // namespace msys_compat
