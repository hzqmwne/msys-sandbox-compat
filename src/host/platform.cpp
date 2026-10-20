#include "host.h"
#include "msys_compat/pe_view.h"
#include <sddl.h>
#include <securityappcontainer.h>
#include <cstdio>
#include <stdexcept>

namespace msys_compat {
AgentState *inherited_agent() {
    // An explicit launcher inside an opted-in tree already has the relay.
    // Its CreateProcess call prepares the child; do not inject it a second time.
    auto entry = reinterpret_cast<const BYTE *>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateUserProcess"));
    if (!entry || entry[0] != 0xe9 || entry[5] != 0x90 || entry[6] != 0x90 || entry[7] != 0x90)
        return nullptr;
    LONG offset = 0;
    memcpy(&offset, entry + 1, sizeof(offset));
    auto handler = entry + 5 + offset;
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(handler, &region, sizeof(region)))
        return nullptr;
    auto base = static_cast<const BYTE *>(region.AllocationBase);
    if (!VirtualQuery(base, &region, sizeof(region)) || region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return nullptr;
    auto pe = PeView(base, region.RegionSize).headers();
    if (!pe || !pe->OptionalHeader.SizeOfImage || pe->OptionalHeader.SizeOfImage > 1024 * 1024)
        return nullptr;
    size_t size = pe->OptionalHeader.SizeOfImage;
    for (size_t at = 0; at < size;) {
        if (!VirtualQuery(base + at, &region, sizeof(region)) || region.AllocationBase != base ||
            region.State != MEM_COMMIT || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return nullptr;
        at = static_cast<const BYTE *>(region.BaseAddress) + region.RegionSize - base;
    }
    PeView view(base, size);
    auto state_rva = view.exported_rva("g_agent_state");
    auto handler_rva = view.exported_rva("hook_process");
    if (!state_rva || !handler_rva || base + handler_rva != handler)
        return nullptr;
    auto state = view.at<AgentState>(state_rva);
    if (!state || !state->native_relay || state->self_base != reinterpret_cast<uintptr_t>(base) ||
        state->self_size != size)
        return nullptr;
    auto &slot = state->hooks[static_cast<size_t>(HookId::create_process)];
    return slot.target == reinterpret_cast<uintptr_t>(entry) &&
                   slot.handler == reinterpret_cast<uintptr_t>(handler) &&
                   reinterpret_cast<uintptr_t>(state->api.create_process) == slot.trampoline
               ? const_cast<AgentState *>(state)
               : nullptr;
}

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
HANDLE configure_security(AgentState &state) {
    // MSYS-created native descendants can deny reopening their primary token.
    // The current-token pseudo handle provides the read-only queries we need.
    HANDLE token = GetCurrentProcessToken();
    BYTE user[4096], package[4096];
    DWORD size = 0;
    check(GetTokenInformation(token, TokenUser, user, sizeof(user), &size), "TokenUser");
    check(GetTokenInformation(token, TokenAppContainerSid, package, sizeof(package), &size),
          "TokenAppContainerSid");
    DWORD default_bytes = 0;
    GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &default_bytes);
    std::vector<BYTE> default_info(default_bytes);
    check(default_bytes && GetTokenInformation(token, TokenDefaultDacl, default_info.data(),
                                               default_bytes, &default_bytes),
          "TokenDefaultDacl");
    auto acl = reinterpret_cast<TOKEN_DEFAULT_DACL *>(default_info.data())->DefaultDacl;
    if (acl) {
        check(IsValidAcl(acl) && acl->AclSize <= sizeof(state.token_default_dacl),
              "sandbox default DACL capacity");
        memcpy(state.token_default_dacl, acl, acl->AclSize);
        state.token_default_dacl_bytes = acl->AclSize;
    }
    auto sid = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer;
    check(sid != nullptr || IsTokenRestricted(token), "restricted execution context required");
    if (sid) {
        LPWSTR user_text = nullptr, package_text = nullptr;
        check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(user)->User.Sid, &user_text),
              "user SID");
        check(ConvertSidToStringSidW(sid, &package_text), "package SID");
        auto sddl = L"D:P(A;;GA;;;" + std::wstring(user_text) + L")(A;;GA;;;SY)(A;;GA;;;" +
                    package_text + L")";
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
    } else {
        SECURITY_DESCRIPTOR descriptor{};
        check(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION),
              "restricted object descriptor");
        check(SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE), "restricted object ACL");
        DWORD bytes = sizeof(state.descriptor);
        check(MakeSelfRelativeSD(&descriptor, state.descriptor, &bytes),
              "restricted descriptor capacity");
    }

    // AppContainer namespaces are supplied by Windows. Restricted tokens need
    // a per-launch directory so unrelated MSYS sessions cannot precreate it
    // with a different ACL. Native intermediaries inherit the launch tag.
    wchar_t relative[object_root_chars]{};
    ULONG chars = 0;
    if (sid)
        check(GetAppContainerNamedObjectPath(token, nullptr, _countof(relative), relative, &chars),
              "AppContainer object namespace");
    else
        wcscpy_s(relative, L"BaseNamedObjects");
    DWORD session = 0;
    check(GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size),
          "TokenSessionId");
    auto root = L"\\Sessions\\" + std::to_wstring(session) + L"\\" + relative;
    HANDLE directory = nullptr;
    if (!sid) {
        wchar_t tag[32]{};
        auto count = GetEnvironmentVariableW(L"MSYS_COMPAT_SESSION", tag, _countof(tag));
        check(count < _countof(tag), "inherited compatibility session");
        for (DWORD i = 0; i < count; ++i)
            check(tag[i] >= L'0' && tag[i] <= L'9', "compatibility session tag");
        auto identity = count ? std::wstring(tag) : std::to_wstring(GetCurrentProcessId());
        check(SetEnvironmentVariableW(L"MSYS_COMPAT_SESSION", identity.c_str()),
              "inherit compatibility session");
        root += L"\\msys-compat-" + identity;
        check(root.size() < object_root_chars, "namespace capacity");
        UNICODE_STRING name{static_cast<USHORT>(root.size() * sizeof(wchar_t)),
                            static_cast<USHORT>((root.size() + 1) * sizeof(wchar_t)), root.data()};
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, nullptr,
                                   state.descriptor);
        check_nt(
            state.api.create_directory(&directory, STANDARD_RIGHTS_REQUIRED | 0xf, &attributes),
            "restricted compatibility namespace");
    }
    check(root.size() < object_root_chars, "namespace capacity");
    memcpy(state.object_root, root.c_str(), (root.size() + 1) * 2);
    state.root_chars = static_cast<uint32_t>(root.size());
    return directory;
}
} // namespace msys_compat
