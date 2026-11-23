#include "host.h"
#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <stdexcept>

namespace msys_sandbox_compat {
namespace {
std::unique_ptr<FILE, decltype(&fclose)> redirected_error(nullptr, fclose);
std::unique_ptr<void, decltype(&CloseHandle)> log_file(nullptr, CloseHandle);
LogLevel log_level = LogLevel::off;

FILE *host_stderr() { return redirected_error ? redirected_error.get() : stderr; }
}

bool log_enabled(LogLevel level) { return log_level >= level; }

HANDLE host_log_file() { return log_file.get(); }

void configure_host_log(LogLevel level, const std::filesystem::path &path) {
    log_level = level;
    if (level == LogLevel::off || path.empty())
        return;
    const auto handle = CreateFileW(path.c_str(), FILE_APPEND_DATA | SYNCHRONIZE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    check(handle != INVALID_HANDLE_VALUE, "open log file");
    log_file.reset(handle);
}

void host_log(LogLevel level, const char *format, ...) {
    if (!log_enabled(level))
        return;
    va_list args;
    va_start(args, format);
    if (log_file) {
        char line[4096];
        const int count = vsnprintf(line, sizeof(line), format, args);
        DWORD written = 0;
        if (count > 0)
            ::WriteFile(log_file.get(), line,
                        static_cast<DWORD>(static_cast<size_t>(count) < sizeof(line)
                                               ? count : sizeof(line) - 1),
                        &written, nullptr);
    } else
        vfprintf(host_stderr(), format, args);
    va_end(args);
}

void configure_agent_log(AgentState &state, bool trace) {
    state.trace = trace;
    state.trace_file = trace ? host_log_file() : nullptr;
    if (!trace)
        return;
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!state.api.write_file) {
        state.api.write_file = reinterpret_cast<decltype(state.api.write_file)>(
            GetProcAddress(ntdll, "NtWriteFile"));
        check(state.api.write_file != nullptr, "resolve NtWriteFile");
    }
    if (state.trace_file && !state.api.duplicate_object) {
        state.api.duplicate_object = reinterpret_cast<DuplicateObject>(
            GetProcAddress(ntdll, "NtDuplicateObject"));
        check(state.api.duplicate_object != nullptr, "resolve NtDuplicateObject");
    }
}

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
        throw std::runtime_error(std::string(operation) + ": Win32 " +
                                 std::to_string(error));
    }
}
void check_nt(NTSTATUS status, const char *operation) {
    if (status < 0) {
        char detail[32];
        snprintf(detail, sizeof(detail), ": NTSTATUS %08lx", static_cast<ULONG>(status));
        throw std::runtime_error(std::string(operation) + detail);
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
    }
    if (state.enabled(Module::token_dacl)) {
        RESOLVE(compare_objects, "NtCompareObjects");
        RESOLVE(set_token, "NtSetInformationToken");
    }
    if (modules & acl_modules) {
        RESOLVE(query_token, "NtQueryInformationToken");
    }
    if (state.enabled(Module::token_dacl)) {
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
