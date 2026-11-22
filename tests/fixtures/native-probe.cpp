#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <filesystem>

int wmain(int argc, wchar_t **argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--file-access") {
        auto read = [](PCWSTR path) {
            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return GetLastError();
            CloseHandle(file);
            return static_cast<DWORD>(ERROR_SUCCESS);
        };
        const auto allowed = read(argv[2]);
        const auto denied = read(argv[3]);
        printf("allowed-read-error=%lu denied-read-error=%lu\n", allowed, denied);
        return allowed == ERROR_SUCCESS && denied == ERROR_ACCESS_DENIED ? 37 : 1;
    }
    FILE *report = stderr;
    bool inspect_parent = argc > 2 && std::wstring(argv[1]) == L"--inspect-parent";
    bool reenter = argc > 3 && std::wstring(argv[1]) == L"--reenter";
    if (argc > 1 && !reenter)
        _wfopen_s(&report, argv[inspect_parent ? 2 : 1], L"w");
    if (!report)
        return 2;
    setvbuf(report, nullptr, _IONBF, 0);
    fprintf(report, "pid=%lu\n", GetCurrentProcessId());
    HANDLE token = nullptr;
    BOOL opened = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    fprintf(report, "token-reopen=%d error=%lu\n", opened, opened ? 0 : GetLastError());
    if (opened)
        CloseHandle(token);
    BYTE token_bytes[4096]{};
    DWORD token_size = 0;
    if (!GetTokenInformation(GetCurrentProcessToken(), TokenDefaultDacl, token_bytes,
                             sizeof(token_bytes), &token_size))
        return 5;
    SECURITY_DESCRIPTOR token_descriptor{};
    InitializeSecurityDescriptor(&token_descriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&token_descriptor, TRUE,
                              reinterpret_cast<TOKEN_DEFAULT_DACL *>(token_bytes)->DefaultDacl,
                              FALSE);
    LPWSTR token_text = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &token_descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &token_text, nullptr))
        return 5;
    fprintf(report, "token-default-dacl=%ls\n", token_text);
    LocalFree(token_text);
    bool clean = true;
    for (auto name : {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
                      "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
                      "NtAllocateVirtualMemory", "NtCreateUserProcess", "NtSetInformationToken",
                      "NtSetSecurityObject"}) {
        auto code =
            reinterpret_cast<const BYTE *>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name));
        bool original =
            code && code[0] == 0x4c && code[1] == 0x8b && code[2] == 0xd1 && code[3] == 0xb8;
        fprintf(report, "%s original=%d\n", name, original);
        clean = clean && original;
    }
    ULONG_PTR port = 1;
    auto query =
        reinterpret_cast<NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    auto status =
        query(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(7), &port, sizeof(port), nullptr);
    fprintf(report, "debug-port-status=%08lx port=%llu\n", static_cast<ULONG>(status), port);
    clean = clean && status >= 0 && port == 0;
    const auto cygheap = reinterpret_cast<void *>(0x800000000ULL);
    MEMORY_BASIC_INFORMATION arena{};
    const auto queried = VirtualQuery(cygheap, &arena, sizeof(arena));
    fprintf(report, "msys-arena-state=%lx\n", arena.State);
    clean = clean && queried && !(arena.State == MEM_RESERVE && arena.AllocationBase == cygheap &&
                                  arena.RegionSize >= 0x200000000ULL);
    if (inspect_parent) {
        PROCESS_BASIC_INFORMATION basic{};
        query(GetCurrentProcess(), ProcessBasicInformation, &basic, sizeof(basic), nullptr);
        HANDLE parent =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                        static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.Reserved3)));
        if (!parent) {
            fprintf(report, "open-parent-failed=%lu\n", GetLastError());
            return 3;
        }
        unsigned jumps = 0;
        bool allocation_original = false;
        for (auto name :
             {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
              "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
              "NtAllocateVirtualMemory", "NtCreateUserProcess", "NtSetInformationToken",
              "NtSetSecurityObject"}) {
            BYTE code[8]{};
            auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
            if (ReadProcessMemory(parent, address, code, sizeof(code), nullptr)) {
                if (code[0] == 0xe9)
                    ++jumps;
                if (std::string(name) == "NtAllocateVirtualMemory")
                    allocation_original = code[0] == 0x4c && code[1] == 0x8b && code[2] == 0xd1 &&
                                          code[3] == 0xb8;
            }
        }
        port = 1;
        status = query(parent, static_cast<PROCESSINFOCLASS>(7), &port, sizeof(port), nullptr);
        fprintf(report, "parent-inline-jumps=%u parent-debug-status=%08lx parent-debug-port=%llu\n",
                jumps, static_cast<ULONG>(status), port);
        clean = clean && jumps == 9 && allocation_original && status >= 0 && port == 0;
        for (auto address : {0x800000000ULL, 0xa00000000ULL}) {
            auto base = reinterpret_cast<void *>(address);
            MEMORY_BASIC_INFORMATION heap{};
            const bool original = VirtualQueryEx(parent, base, &heap, sizeof(heap)) &&
                                  heap.AllocationBase == base && heap.State == MEM_COMMIT;
            fprintf(report, "parent-heap=%p committed-at-original=%d\n", base, original);
            clean = clean && original;
        }
        CloseHandle(parent);
    }
    fprintf(report, "clean=%d\n", clean);
    if (argc > 1 && !reenter)
        fclose(report);
    if (reenter) {
        auto runtime = std::filesystem::path(argv[3]).parent_path() / L"msys-2.0.dll";
        std::wstring command = L"\"" + std::wstring(argv[2]) + L"\" --no-native-relay --runtime \"" +
                               runtime.wstring() + L"\" \"" + argv[3] +
                               L"\" --noprofile --norc -c \"echo EXPLICIT-REENTRY\"";
        STARTUPINFOW startup{sizeof(startup)};
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION child{};
        if (!CreateProcessW(argv[2], command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                            &startup, &child))
            return 4;
        WaitForSingleObject(child.hProcess, INFINITE);
        DWORD result = 1;
        GetExitCodeProcess(child.hProcess, &result);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        return static_cast<int>(result);
    }
    return clean ? 0 : 1;
}
