#include "host.h"
#include <cstdio>
#include <stdexcept>

namespace msys_sandbox_compat {
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
    RESOLVE(query_security, "NtQuerySecurityObject");
    RESOLVE(compare_objects, "NtCompareObjects");
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
} // namespace msys_sandbox_compat
