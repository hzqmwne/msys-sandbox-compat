#include "host.h"
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <stdexcept>

namespace msys_sandbox_compat {
namespace {
std::unique_ptr<FILE, decltype(&fclose)> redirected_error(nullptr, fclose);
}

FILE *host_stderr() { return redirected_error ? redirected_error.get() : stderr; }

void redirect_host_stderr(HANDLE handle) {
    // Keep the original console handle alive. The CRT stream owns a separate
    // non-inheritable copy for messages from the session owner itself.
    HANDLE copy = nullptr;
    const HANDLE self = GetCurrentProcess();
    check(DuplicateHandle(self, handle, self, &copy, 0, FALSE, DUPLICATE_SAME_ACCESS),
          "duplicate session diagnostics handle");
    const int descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(copy), _O_WRONLY | _O_TEXT);
    if (descriptor == -1) {
        CloseHandle(copy);
        throw std::runtime_error("open session diagnostics descriptor");
    }
    redirected_error.reset(_fdopen(descriptor, "w"));
    if (!redirected_error) {
        _close(descriptor);
        throw std::runtime_error("open session diagnostics stream");
    }
    setvbuf(host_stderr(), nullptr, _IONBF, 0);
    // The inherited agent resolves its trace handle from the Win32 process parameters.
    check(SetStdHandle(STD_ERROR_HANDLE, copy), "set session diagnostics handle");
}

void check(bool success, const char *operation) {
    if (!success) {
        const auto error = GetLastError();
        fprintf(host_stderr(), "[error] %s: Win32 %lu\n", operation, error);
        throw std::runtime_error(operation);
    }
}
void check_nt(NTSTATUS status, const char *operation) {
    if (status < 0) {
        fprintf(host_stderr(), "[error] %s: NTSTATUS %08lx\n", operation,
                static_cast<ULONG>(status));
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
        RESOLVE(unmap_section, "NtUnmapViewOfSection");
    }
    if (modules & (file_images | bit(Module::ipc))) {
        RESOLVE(create_section, "NtCreateSection");
    }
    if (modules & (file_images | bit(Module::dll_placement))) {
        RESOLVE(map_section, "NtMapViewOfSection");
    }
    if (modules & (bit(Module::dll_placement) | bit(Module::exe_placement))) {
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
        RESOLVE(create_process, "NtCreateUserProcess");
    }
    const auto hooks = selected_hooks(modules);
    if (hooks || state.enabled(Module::exe_placement)) {
        RESOLVE(terminate, "NtTerminateProcess");
    }
    if (hooks) {
        RESOLVE(add_function_table, "RtlAddFunctionTable");
    }
#undef RESOLVE
    return api;
}
} // namespace msys_sandbox_compat
