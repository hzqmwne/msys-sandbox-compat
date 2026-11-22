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

static bool read_redirected_input(HANDLE input) {
    DWORD count = 0;
    char data[2]{};
    return ReadFile(input, data, sizeof(data), &count, nullptr) && count == 1 && data[0] == 'A' &&
           ReadFile(input, data, sizeof(data), &count, nullptr) && !count;
}

static const unsigned char redirected_bytes[] = {'S', 'T', 'D', 'I', 'O', 0, 0xff, '\r', '\n', '1'};

static int check_mixed_pipe() {
    unsigned char received[sizeof(redirected_bytes)];
    size_t used = 0;
    auto input = GetStdHandle(STD_INPUT_HANDLE);
    while (used < sizeof(received)) {
        DWORD count = 0;
        if (!ReadFile(input, received + used, static_cast<DWORD>(sizeof(received) - used), &count,
                      nullptr) || !count)
            return 23;
        used += count;
    }
    DWORD count;
    unsigned char extra;
    if (memcmp(received, redirected_bytes, sizeof(received)) ||
        ReadFile(input, &extra, 1, &count, nullptr) || GetLastError() != ERROR_BROKEN_PIPE)
        return 24;
    puts("STDIO-MIXED-PIPE-EOF");
    return 37;
}

static int mixed_stdio(std::wstring_view mask, bool expect_bridge) {
    if (mask.size() != 3 || mask.find_first_not_of(L"01") != mask.npos)
        return 12;
    const HANDLE streams[] = {GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE),
                              GetStdHandle(STD_ERROR_HANDLE)};
    for (size_t i = 0; i < mask.size(); ++i) {
        DWORD mode = 0;
        if ((GetConsoleMode(streams[i], &mode) != FALSE) != (mask[i] == L'1'))
            return 13;
    }
    if (mask[0] == L'0' && !read_redirected_input(streams[0]))
        return 14;

    const DWORD access = GENERIC_READ | GENERIC_WRITE;
    const DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
    const HANDLE input = CreateFileW(L"CONIN$", access, sharing, nullptr, OPEN_EXISTING, 0, nullptr);
    const HANDLE output = CreateFileW(L"CONOUT$", access, sharing, nullptr, OPEN_EXISTING, 0, nullptr);
    if (input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE)
        return 18;
    wchar_t cell;
    DWORD count = 0;
    const BOOL read = ReadConsoleOutputCharacterW(output, &cell, 1, {0, 0}, &count);
    const bool screen_matches = expect_bridge ? read && count == 1
                                              : !read && GetLastError() == ERROR_ACCESS_DENIED;
    INPUT_RECORD event{};
    event.EventType = KEY_EVENT;
    event.Event.KeyEvent.wVirtualKeyCode = VK_F24;
    event.Event.KeyEvent.wRepeatCount = 1;
    const BOOL wrote = WriteConsoleInputW(input, &event, 1, &count);
    const bool input_matches = expect_bridge ? wrote && count == 1
                                             : !wrote && GetLastError() == ERROR_ACCESS_DENIED;
    CloseHandle(input);
    if (!screen_matches || !input_matches) {
        fprintf(stderr, "STDIO terminal access: screen=%d input=%d wanted bridge=%d\n",
                read, wrote, expect_bridge);
        CloseHandle(output);
        return 19;
    }
    constexpr wchar_t terminal_marker[] = L"STDIO-TERMINAL\r\n";
    if (expect_bridge &&
        !WriteConsoleW(output, terminal_marker, _countof(terminal_marker) - 1, &count, nullptr)) {
        CloseHandle(output);
        return 20;
    }
    CloseHandle(output);

    for (size_t i = 1; i < mask.size(); ++i) {
        if (mask[i] == L'1') {
            const char *marker = i == 1 ? "STDIO-OUT\r\n" : "STDIO-ERR\r\n";
            const auto length = static_cast<DWORD>(strlen(marker));
            if (!WriteFile(streams[i], marker, length, &count, nullptr) || count != length)
                return 21;
        } else {
            unsigned char data[sizeof(redirected_bytes)];
            memcpy(data, redirected_bytes, sizeof(data));
            data[sizeof(data) - 1] = static_cast<unsigned char>('0' + i);
            if (!WriteFile(streams[i], data, sizeof(data), &count, nullptr) || count != sizeof(data))
                return 22;
        }
    }
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
    if ((mode == L"--mixed-console" || mode == L"--mixed-direct") && argc == 3)
        return mixed_stdio(argv[2], mode == L"--mixed-console");
    if (mode == L"--check-mixed-pipe")
        return check_mixed_pipe();
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
