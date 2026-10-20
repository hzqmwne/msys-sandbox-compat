#include "host.h"
#include <sddl.h>
#include <securityappcontainer.h>
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
std::wstring quote(const std::wstring &text) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (auto c : text) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        out.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (c == L'"')
            out += L'\\';
        out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L'"';
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
    RESOLVE(create_process, "NtCreateUserProcess");
    RESOLVE(create_directory, "NtCreateDirectoryObject");
    RESOLVE(create_mutant, "NtCreateMutant");
    RESOLVE(create_link, "NtCreateSymbolicLinkObject");
    RESOLVE(create_pipe, "NtCreateNamedPipeFile");
    RESOLVE(add_function_table, "RtlAddFunctionTable");
#undef RESOLVE
    return api;
}
void configure_security(AgentState &state) {
    // MSYS-created native descendants can deny reopening their primary token.
    // The current-token pseudo handle provides the read-only queries we need.
    HANDLE token = GetCurrentProcessToken();
    BYTE user[4096], package[4096];
    DWORD size = 0;
    check(GetTokenInformation(token, TokenUser, user, sizeof(user), &size), "TokenUser");
    check(GetTokenInformation(token, TokenAppContainerSid, package, sizeof(package), &size),
          "TokenAppContainerSid");
    auto sid = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer;
    check(sid != nullptr, "launcher must run inside PSEC");
    LPWSTR user_text = nullptr, package_text = nullptr;
    check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(user)->User.Sid, &user_text),
          "user SID");
    check(ConvertSidToStringSidW(sid, &package_text), "package SID");
    auto sddl =
        L"D:P(A;;GA;;;" + std::wstring(user_text) + L")(A;;GA;;;SY)(A;;GA;;;" + package_text + L")";
    LocalFree(user_text);
    LocalFree(package_text);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ULONG bytes = 0;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                               &descriptor, &bytes),
          "private object descriptor");
    check(bytes <= sizeof(state.descriptor), "descriptor capacity");
    memcpy(state.descriptor, descriptor, bytes);
    LocalFree(descriptor);

    // Named Win32 object creation may also reopen that token while resolving
    // the namespace. Query its path directly instead of creating a probe event.
    wchar_t relative[object_root_chars]{};
    ULONG chars = 0;
    check(GetAppContainerNamedObjectPath(token, nullptr, _countof(relative), relative, &chars),
          "AppContainer object namespace");
    DWORD session = 0;
    check(GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size),
          "TokenSessionId");
    auto root = L"\\Sessions\\" + std::to_wstring(session) + L"\\" + relative;
    check(root.size() < object_root_chars, "namespace capacity");
    memcpy(state.object_root, root.c_str(), (root.size() + 1) * 2);
    state.root_chars = static_cast<uint32_t>(root.size());
}
} // namespace msys_compat
