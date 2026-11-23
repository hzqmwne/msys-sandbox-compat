#include "msys_sandbox_compat/command_line.h"
using msys_sandbox_compat::quote;
#include <windows.h>
#include <sddl.h>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::wstring default_dacl_text(PACL acl) {
    SECURITY_DESCRIPTOR descriptor{};
    LPWSTR text = nullptr;
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
        !ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &descriptor, 1, DACL_SECURITY_INFORMATION, &text, nullptr))
        return {};
    std::wstring result(text);
    LocalFree(text);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    int first = 1;
    bool relay = first < argc && std::wstring(argv[first]) == L"--relay";
    if (relay)
        ++first;
    bool change_default = first < argc && std::wstring(argv[first]) == L"--change-default";
    if (change_default)
        ++first;
    bool suspended = first < argc && std::wstring(argv[first]) == L"--suspended";
    if (suspended)
        ++first;
    if (argc < first + 2)
        return 2;
    wchar_t *end = nullptr;
    unsigned long depth = wcstoul(argv[first], &end, 10);
    if (!end || *end || depth > 8)
        return 2;
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    for (const char *name :
         {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
          "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
          "NtAllocateVirtualMemory", "NtCreateUserProcess", "NtSetInformationToken",
          "NtSetSecurityObject"}) {
        auto code = reinterpret_cast<const BYTE *>(GetProcAddress(ntdll, name));
        bool create = std::string(name) == "NtCreateUserProcess";
        bool expected = code && (relay && create ? code[0] == 0xe9
                                                 : code[0] == 0x4c && code[1] == 0x8b &&
                                                       code[2] == 0xd1 && code[3] == 0xb8);
        if (!expected)
            return 3;
    }
    using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
    auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    ULONG_PTR debug_port = 1;
    const auto cygheap = reinterpret_cast<void *>(0x800000000ULL);
    MEMORY_BASIC_INFORMATION region{};
    if (query(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr) < 0 || debug_port ||
        !VirtualQuery(cygheap, &region, sizeof(region)) ||
        (region.State == MEM_RESERVE && region.AllocationBase == cygheap &&
         region.RegionSize >= 0x200000000ULL))
        return 3;
    BYTE info[4096]{};
    DWORD bytes = 0;
    if (!GetTokenInformation(GetCurrentProcessToken(), TokenDefaultDacl, info, sizeof(info),
                             &bytes))
        return 4;
    const auto original_acl = reinterpret_cast<TOKEN_DEFAULT_DACL *>(info)->DefaultDacl;
    const auto text = default_dacl_text(original_acl);
    if (text.empty())
        return 4;
    fprintf(stderr, "[bridge] clean=1 depth=%lu default=%ls\n", depth, text.c_str());
    if (relay)
        fprintf(stderr, "[bridge-mode] relay=1 hooks=1\n");
    wchar_t own_path[32768]{};
    if (depth && !GetModuleFileNameW(nullptr, own_path, _countof(own_path)))
        return 4;
    std::wstring executable = depth ? own_path : argv[first + 1];
    std::wstring command = quote(executable);
    if (depth) {
        if (relay)
            command += L" --relay";
        if (suspended)
            command += L" --suspended";
        command += L" " + std::to_wstring(depth - 1);
    }
    for (int i = depth ? first + 1 : first + 2; i < argc; ++i)
        command += L" " + quote(argv[i]);
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child{};
    HANDLE token = nullptr;
    if (change_default) {
        // Change the ACL bytes without changing any effective permissions.
        BYTE system[SECURITY_MAX_SID_SIZE];
        DWORD sid_bytes = sizeof(system);
        if (!original_acl || !CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &sid_bytes))
            return 7;
        const auto size = original_acl->AclSize + offsetof(ACCESS_ALLOWED_ACE, SidStart) +
                          sid_bytes;
        if (size > MAXWORD)
            return 7;
        std::vector<BYTE> data(size);
        memcpy(data.data(), original_acl, original_acl->AclSize);
        const auto acl = reinterpret_cast<PACL>(data.data());
        acl->AclSize = static_cast<WORD>(size);
        if (!AddAccessAllowedAce(acl, acl->AclRevision, 0, system))
            return 7;
        const auto changed = default_dacl_text(acl);
        if (changed.empty() || changed == text ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &token))
            return 7;
        TOKEN_DEFAULT_DACL replacement{acl};
        if (!SetTokenInformation(token, TokenDefaultDacl, &replacement, sizeof(replacement))) {
            fprintf(stderr, "[bridge] change default error=%lu\n", GetLastError());
            CloseHandle(token);
            return 7;
        }
        fprintf(stderr, "[bridge] changed-default=%ls\n", changed.c_str());
    }
    BOOL created =
        CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                       suspended ? CREATE_SUSPENDED : 0, nullptr, nullptr, &startup, &child);
    DWORD creation_error = created ? 0 : GetLastError();
    if (change_default) {
        BOOL restored = SetTokenInformation(token, TokenDefaultDacl, info, bytes);
        fprintf(stderr, "[bridge] changed created=%d error=%lu restored=%d restore-error=%lu\n",
                created, creation_error, restored, restored ? 0 : GetLastError());
        CloseHandle(token);
        if (!restored) {
            if (created) {
                TerminateProcess(child.hProcess, 7);
                CloseHandle(child.hThread);
                CloseHandle(child.hProcess);
            }
            return 7;
        }
    }
    if (!created)
        return 5;
    if (suspended) {
        auto count = ResumeThread(child.hThread);
        if (count != 1) {
            TerminateProcess(child.hProcess, 8);
            CloseHandle(child.hThread);
            CloseHandle(child.hProcess);
            return 8;
        }
        fprintf(stderr, "[bridge-mode] suspended-preserved=1\n");
    }
    DWORD result = 6;
    if (WaitForSingleObject(child.hProcess, 60000) == WAIT_OBJECT_0)
        GetExitCodeProcess(child.hProcess, &result);
    else
        TerminateProcess(child.hProcess, result);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return static_cast<int>(result);
}
