#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>

static std::wstring quote(const std::wstring &value) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        result.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (c == L'"')
            result += L'\\';
        result += c;
    }
    result.append(slashes * 2, L'\\');
    return result + L'"';
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3)
        return 2;
    wchar_t *end = nullptr;
    unsigned long depth = wcstoul(argv[1], &end, 10);
    if (!end || *end || depth > 8)
        return 2;
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    for (const char *name :
         {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
          "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
          "NtAllocateVirtualMemory", "NtCreateUserProcess", "NtSetInformationToken"}) {
        auto code = reinterpret_cast<const BYTE *>(GetProcAddress(ntdll, name));
        if (!code || code[0] != 0x4c || code[1] != 0x8b || code[2] != 0xd1 || code[3] != 0xb8)
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
    LocalFree(text);
    wchar_t own_path[32768]{};
    if (depth && !GetModuleFileNameW(nullptr, own_path, _countof(own_path)))
        return 4;
    std::wstring executable = depth ? own_path : argv[2];
    std::wstring command = quote(executable);
    if (depth)
        command += L" " + std::to_wstring(depth - 1);
    for (int i = depth ? 2 : 3; i < argc; ++i)
        command += L" " + quote(argv[i]);
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
                        nullptr, &startup, &child))
        return 5;
    DWORD result = 6;
    if (WaitForSingleObject(child.hProcess, 60000) == WAIT_OBJECT_0)
        GetExitCodeProcess(child.hProcess, &result);
    else
        TerminateProcess(child.hProcess, result);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return static_cast<int>(result);
}
