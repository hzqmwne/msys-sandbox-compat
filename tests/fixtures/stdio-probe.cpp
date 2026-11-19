#include "msys_sandbox_compat/command_line.h"
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
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

static bool read_console_input_byte() {
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0, count = 0;
    char byte = 0;
    return GetConsoleMode(input, &mode) &&
           SetConsoleMode(input, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) &&
           ReadFile(input, &byte, 1, &count, nullptr) && count == 1 && byte == 'A';
}

static int write_console_burst() {
    puts("CONPTY-PIPE-READY");
    if (fflush(stdout) || !read_console_input_byte())
        return 15;

    char buffer[4096];
    memset(buffer, 'x', sizeof(buffer));
    for (size_t i = 63; i < sizeof(buffer); i += 64)
        buffer[i] = '\n';
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    for (int i = 0; i < 400; ++i) {
        DWORD count = 0;
        buffer[0] = static_cast<char>('A' + i % 26);
        if (!WriteFile(output, buffer, sizeof(buffer), &count, nullptr) || count != sizeof(buffer))
            return 16;
    }
    puts("CONPTY-BURST-COMPLETE");
    return 37;
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

static int redirected_input() {
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0, count = 0;
    char data[2]{};
    if (GetFileType(input) != FILE_TYPE_DISK ||
        !GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) ||
        !GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode) ||
        !ReadFile(input, data, sizeof(data), &count, nullptr) || count != 1 || data[0] != 'A' ||
        !ReadFile(input, data, sizeof(data), &count, nullptr) || count != 0)
        return 18;
    puts("STDIO-CONSOLE");
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
    if (mode == L"--conpty-burst")
        return write_console_burst();
    if (mode == L"--conpty-read-one") {
        if (!read_console_input_byte())
            return 17;
        puts("CONPTY-INPUT-COMPLETE");
        return 37;
    }
    if (mode == L"--mixed-stdout" || mode == L"--mixed-stderr")
        return mixed_stdio(mode == L"--mixed-stdout");
    if (mode == L"--mixed-stdin")
        return redirected_input();
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
