#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <filesystem>
#include <vector>

static bool handle_survived(HANDLE handle) {
    // Diagnostic only: PSEC's permanent strict-handle policy can raise even
    // when querying a value FreeConsole has already closed. Do not suppress
    // this exception in the production agent.
    __try {
        DWORD flags = 0;
        return GetHandleInformation(handle, &flags) != FALSE;
    } __except (GetExceptionCode() == 0xc0000008 ? EXCEPTION_EXECUTE_HANDLER
                                                 : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

int wmain(int argc, wchar_t **argv) {
    FILE *report = stderr;
    bool inspect_parent = argc > 2 && std::wstring(argv[1]) == L"--inspect-parent";
    bool reenter = argc > 3 && std::wstring(argv[1]) == L"--reenter";
    if (argc > 1 && !reenter)
        _wfopen_s(&report, argv[inspect_parent ? 2 : 1], L"w");
    if (!report)
        return 2;
    setvbuf(report, nullptr, _IONBF, 0);
    fprintf(report, "pid=%lu\n", GetCurrentProcessId());
    bool clean = true;
    for (auto name : {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
                      "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
                      "NtAllocateVirtualMemory", "NtCreateUserProcess"}) {
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
    MEMORY_BASIC_INFORMATION arena{};
    VirtualQuery(reinterpret_cast<void *>(0x80000000000ULL), &arena, sizeof(arena));
    fprintf(report, "msys-arena-state=%lx\n", arena.State);
    clean = clean && arena.State == MEM_FREE;
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
        for (auto name : {"NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
                          "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile",
                          "NtMapViewOfSection", "NtAllocateVirtualMemory", "NtCreateUserProcess"}) {
            BYTE code[8]{};
            auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
            if (ReadProcessMemory(parent, address, code, sizeof(code), nullptr) &&
                code[0] == 0xe9 && code[5] == 0x90 && code[6] == 0x90 && code[7] == 0x90)
                ++jumps;
        }
        port = 1;
        status = query(parent, static_cast<PROCESSINFOCLASS>(7), &port, sizeof(port), nullptr);
        fprintf(report, "parent-inline-jumps=%u parent-debug-status=%08lx parent-debug-port=%llu\n",
                jumps, static_cast<ULONG>(status), port);
        clean = clean && jumps == 8 && status >= 0 && port == 0;
        CloseHandle(parent);
    }
    for (DWORD id : {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        auto handle = GetStdHandle(id);
        DWORD mode = 0;
        BOOL console = GetConsoleMode(handle, &mode);
        DWORD console_error = console ? 0 : GetLastError();
        DWORD handle_flags = 0;
        BOOL handle_info = GetHandleInformation(handle, &handle_flags);
        fprintf(report, "stdio=%ld handle=%p type=%lu console=%d error=%lu mode=%lx\n", id, handle,
                GetFileType(handle), console, console_error, mode);
        fprintf(report, "handle-info=%d flags=%lx\n", handle_info, handle_flags);
        PUBLIC_OBJECT_BASIC_INFORMATION object_basic{};
        auto query_object =
            reinterpret_cast<NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG)>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
        auto object_status = query_object(handle, 0, &object_basic, sizeof(object_basic), nullptr);
        fprintf(report, "object-basic-status=%08lx granted-access=%08lx\n",
                static_cast<ULONG>(object_status), object_basic.GrantedAccess);
    }
    for (auto name : {L"CONIN$", L"CONOUT$"}) {
        HANDLE handle =
            CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        fprintf(report, "%ls handle=%p error=%lu\n", name, handle,
                handle == INVALID_HANDLE_VALUE ? GetLastError() : 0);
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
    printf("NATIVE-PROBE-CLEAN=%d\n", clean);
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strict{};
    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessStrictHandleCheckPolicy, &strict,
                                   sizeof(strict)))
        fprintf(report, "strict-handle-policy=%lx\n", strict.Flags);
    DWORD written = 0;
    BOOL output = WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"CONSOLE-WRITE-OK\r\n", 18,
                                &written, nullptr);
    fprintf(report, "WriteConsole ok=%d written=%lu error=%lu\n", output, written,
            output ? 0 : GetLastError());
    output = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "FILE-WRITE-OK\r\n", 15, &written, nullptr);
    fprintf(report, "WriteFile ok=%d written=%lu error=%lu\n", output, written,
            output ? 0 : GetLastError());
    fprintf(report, "clean=%d\n", clean);
    if (argc > 2 && std::wstring(argv[2]) == L"--write-console-input") {
        INPUT_RECORD record{};
        record.EventType = KEY_EVENT;
        record.Event.KeyEvent.bKeyDown = TRUE;
        record.Event.KeyEvent.wRepeatCount = 1;
        record.Event.KeyEvent.wVirtualKeyCode = 'Q';
        record.Event.KeyEvent.uChar.UnicodeChar = L'Q';
        fprintf(report, "before-WriteConsoleInputW\n");
        DWORD count = 0;
        BOOL result = WriteConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &count);
        fprintf(report, "WriteConsoleInputW=%d count=%lu error=%lu\n", result, count,
                result ? 0 : GetLastError());
    }
    if (argc > 2 && std::wstring(argv[2]) == L"--console-lifetime") {
        for (auto id : {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
            HANDLE handle = GetStdHandle(id);
            fprintf(report, "close-standard=%p\n", handle);
            CloseHandle(handle);
        }
        std::vector<HANDLE> mutexes;
        for (unsigned i = 0; i < 32; ++i)
            mutexes.push_back(CreateMutexW(nullptr, FALSE, nullptr));
        fprintf(report, "before-FreeConsole\n");
        BOOL detached = FreeConsole();
        // Inspect before opening the report: that open could itself reuse a
        // lost mutex's numeric handle and conceal the stale-close evidence.
        bool valid[32]{};
        for (unsigned i = 0; i < 32; ++i)
            valid[i] = handle_survived(mutexes[i]);
        FILE *after = nullptr;
        auto after_path = std::wstring(argv[1]) + L".after.txt";
        _wfopen_s(&after, after_path.c_str(), L"w");
        if (!after)
            ExitProcess(2);
        setvbuf(after, nullptr, _IONBF, 0);
        fprintf(after, "FreeConsole=%d\n", detached);
        unsigned lost = 0;
        for (unsigned i = 0; i < 32; ++i) {
            if (!valid[i]) {
                ++lost;
                fprintf(after, "lost-mutex=%p\n", mutexes[i]);
            }
        }
        fprintf(after, "lost-mutex-count=%u\n", lost);
        fclose(after);
        // The deliberate stdio close leaves CRT's stream handles stale.
        ExitProcess(0);
    }
    if (argc > 1 && !reenter)
        fclose(report);
    if (reenter) {
        auto runtime = std::filesystem::path(argv[3]).parent_path() / L"msys-2.0.dll";
        std::wstring command = L"\"" + std::wstring(argv[2]) + L"\" --runtime \"" +
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
