#include "msys_compat/command_line.h"
using msys_compat::quote;
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>

int wmain(int argc, wchar_t **argv) {
    int first = 1;
    bool relay = first < argc && std::wstring(argv[first]) == L"--relay";
    if (relay)
        ++first;
    bool narrow = first < argc && std::wstring(argv[first]) == L"--narrow-default";
    if (narrow)
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
          "NtAllocateVirtualMemory", "NtCreateUserProcess", "NtSetInformationToken"}) {
        auto code = reinterpret_cast<const BYTE *>(GetProcAddress(ntdll, name));
        bool create = std::string(name) == "NtCreateUserProcess";
        bool expected = code && (relay && create ? code[0] == 0xe9 && code[5] == 0x90 &&
                                                       code[6] == 0x90 && code[7] == 0x90
                                                 : code[0] == 0x4c && code[1] == 0x8b &&
                                                       code[2] == 0xd1 && code[3] == 0xb8);
        if (!expected)
            return 3;
    }
    using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
    auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    ULONG_PTR debug_port = 1;
    MEMORY_BASIC_INFORMATION region{};
    if (query(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr) < 0 || debug_port ||
        !VirtualQuery(reinterpret_cast<void *>(0x80000000000ULL), &region, sizeof(region)) ||
        region.State != MEM_FREE)
        return 3;
    BYTE info[4096]{};
    DWORD bytes = 0;
    if (!GetTokenInformation(GetCurrentProcessToken(), TokenDefaultDacl, info, sizeof(info),
                             &bytes))
        return 4;
    SECURITY_DESCRIPTOR descriptor{};
    InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&descriptor, TRUE,
                              reinterpret_cast<TOKEN_DEFAULT_DACL *>(info)->DefaultDacl, FALSE);
    LPWSTR text = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &descriptor, 1, DACL_SECURITY_INFORMATION, &text, nullptr))
        return 4;
    fprintf(stderr, "[bridge] clean=1 depth=%lu default=%ls\n", depth, text);
    if (relay)
        fprintf(stderr, "[bridge-mode] relay=1 hooks=1\n");
    LocalFree(text);
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
    PSECURITY_DESCRIPTOR narrowed = nullptr;
    if (narrow) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &token) ||
            !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)", 1, &narrowed,
                                                                  nullptr)) {
            fprintf(stderr, "[bridge] narrow setup error=%lu\n", GetLastError());
            return 7;
        }
        PACL acl = nullptr;
        BOOL present = FALSE, inherited = FALSE;
        GetSecurityDescriptorDacl(narrowed, &present, &acl, &inherited);
        TOKEN_DEFAULT_DACL replacement{acl};
        if (!SetTokenInformation(token, TokenDefaultDacl, &replacement, sizeof(replacement))) {
            fprintf(stderr, "[bridge] narrow default error=%lu\n", GetLastError());
            return 7;
        }
    }
    BOOL created =
        CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                       suspended ? CREATE_SUSPENDED : 0, nullptr, nullptr, &startup, &child);
    DWORD creation_error = created ? 0 : GetLastError();
    if (narrow) {
        BOOL restored = SetTokenInformation(token, TokenDefaultDacl, info, bytes);
        fprintf(stderr, "[bridge] narrowed created=%d error=%lu restored=%d restore-error=%lu\n",
                created, creation_error, restored, restored ? 0 : GetLastError());
        CloseHandle(token);
        LocalFree(narrowed);
        if (created) {
            TerminateProcess(child.hProcess, 7);
            CloseHandle(child.hThread);
            CloseHandle(child.hProcess);
        }
        if (!created && creation_error == ERROR_ACCESS_DENIED && restored) {
            puts("RELAY-NARROWED-POLICY-REJECTED");
            return 0;
        }
        return 7;
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
