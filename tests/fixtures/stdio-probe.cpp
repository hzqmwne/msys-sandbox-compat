#include "msys_sandbox_compat/command_line.h"
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <fcntl.h>
#include <io.h>
#include <string_view>

static int echo_until_eof() {
    if (_setmode(_fileno(stdin), _O_BINARY) < 0 || _setmode(_fileno(stdout), _O_BINARY) < 0)
        return 1;

    char buffer[8192];
    while (const auto count = fread(buffer, 1, sizeof(buffer), stdin)) {
        if (fwrite(buffer, 1, count, stdout) != count)
            return 2;
    }
    if (ferror(stdin) || !feof(stdin) || fflush(stdout) != 0)
        return 3;
    fputs("STDIO-EOF\n", stderr);
    return 37;
}

static int start_descendant() {
    wchar_t self[32768];
    const auto size = GetModuleFileNameW(nullptr, self, _countof(self));
    if (!size || size == _countof(self))
        return 4;

    HANDLE parent = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &parent,
                         SYNCHRONIZE, TRUE, 0))
        return 5;

    auto command = msys_sandbox_compat::quote(self) + L" --after-parent " +
                   std::to_wstring(reinterpret_cast<ULONG_PTR>(parent));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const BOOL started = CreateProcessW(self, command.data(), nullptr, nullptr, TRUE, 0, nullptr,
                                        nullptr, &startup, &child);
    CloseHandle(parent);
    if (!started)
        return 6;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return 37;
}

static int write_until_pipe_closes() {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    constexpr char ready[] = "PIPE-READY\n";
    DWORD written = 0;
    if (!WriteFile(output, ready, sizeof(ready) - 1, &written, nullptr) ||
        written != sizeof(ready) - 1)
        return 9;
    char buffer[8192]{};
    for (int i = 0; i < 1024; ++i) {
        if (!WriteFile(output, buffer, sizeof(buffer), &written, nullptr)) {
            if (GetLastError() != ERROR_BROKEN_PIPE)
                return 10;
            fputs("PIPE-CLOSED\n", stderr);
            return 37;
        }
    }
    return 11;
}

static int mixed_stdio(bool redirect_stdout) {
    HANDLE redirected = GetStdHandle(redirect_stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    HANDLE console = GetStdHandle(redirect_stdout ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) || !GetConsoleMode(console, &mode) ||
        GetFileType(redirected) != FILE_TYPE_DISK)
        return 12;

    const unsigned char data[] = {'S', 'T', 'D', 'I', 'O', 0, 0xff, '\r', '\n'};
    DWORD written = 0;
    if (!WriteFile(redirected, data, sizeof(data), &written, nullptr) || written != sizeof(data))
        return 13;
    constexpr char marker[] = "STDIO-CONSOLE\r\n";
    if (!WriteFile(console, marker, sizeof(marker) - 1, &written, nullptr) ||
        written != sizeof(marker) - 1)
        return 14;
    return 37;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2)
        return 7;
    const std::wstring_view mode(argv[1]);
    if (mode == L"--echo")
        return echo_until_eof();
    if (mode == L"--descendant")
        return start_descendant();
    if (mode == L"--pipe-close")
        return write_until_pipe_closes();
    if (mode == L"--mixed-stdout" || mode == L"--mixed-stderr")
        return mixed_stdio(mode == L"--mixed-stdout");
    if (mode == L"--after-parent" && argc == 3) {
        const auto parent = reinterpret_cast<HANDLE>(std::wcstoull(argv[2], nullptr, 10));
        const auto waited = WaitForSingleObject(parent, 10000);
        CloseHandle(parent);
        if (waited != WAIT_OBJECT_0 || fputs("DESCENDANT-TAIL\n", stdout) == EOF || fflush(stdout))
            return 8;
        return 43;
    }
    return 7;
}
