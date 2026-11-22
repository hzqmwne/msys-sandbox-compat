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
NativeApi resolve_api(const AgentState &state) {
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
    RESOLVE(write_file, "NtWriteFile");
    RESOLVE(flush_code, "NtFlushInstructionCache");
    RESOLVE(close, "NtClose");
    const auto modules = state.modules();
    const auto file_images = bit(Module::heap_window) | bit(Module::exe_placement);
    if (modules & file_images) {
        RESOLVE(open_file, "NtOpenFile");
    }
    if (modules & (file_images | bit(Module::ipc))) {
        RESOLVE(create_section, "NtCreateSection");
    }
    if (modules & (file_images | bit(Module::dll_placement))) {
        RESOLVE(map_section, "NtMapViewOfSection");
    }
    if (state.enabled(Module::heap_window)) {
        RESOLVE(unmap_section, "NtUnmapViewOfSection");
    }
    if (state.enabled(Module::exe_placement)) {
        RESOLVE(get_context, "NtGetContextThread");
        RESOLVE(set_context, "NtSetContextThread");
        RESOLVE(read_file, "NtReadFile");
    }
    if (state.enabled(Module::dll_placement)) {
        RESOLVE(query_section, "NtQuerySection");
    }
    if (state.enabled(Module::ipc)) {
        RESOLVE(query_object, "NtQueryObject");
        RESOLVE(create_directory, "NtCreateDirectoryObject");
        RESOLVE(create_mutant, "NtCreateMutant");
        RESOLVE(create_link, "NtCreateSymbolicLinkObject");
        RESOLVE(create_pipe, "NtCreateNamedPipeFile");
    }
    if (state.enabled(Module::process_dacl)) {
        RESOLVE(set_security, "NtSetSecurityObject");
        RESOLVE(query_security, "NtQuerySecurityObject");
    }
    if (state.enabled(Module::token_dacl)) {
        RESOLVE(compare_objects, "NtCompareObjects");
        RESOLVE(set_token, "NtSetInformationToken");
    }
    if ((modules & acl_modules) || state.native_relay) {
        RESOLVE(query_token, "NtQueryInformationToken");
    }
    if (state.enabled(Module::token_dacl) || state.native_relay) {
        RESOLVE(open_token, "NtOpenProcessToken");
    }
    if (state.enabled(Module::propagation)) {
        RESOLVE(resume, "NtResumeThread");
        RESOLVE(terminate, "NtTerminateProcess");
        RESOLVE(create_process, "NtCreateUserProcess");
    }
    if (selected_hooks(modules)) {
        RESOLVE(add_function_table, "RtlAddFunctionTable");
    }
#undef RESOLVE
    return api;
}
} // namespace msys_sandbox_compat
