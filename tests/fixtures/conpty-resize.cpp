#include "msys_sandbox_compat/command_line.h"
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

static constexpr COORD initial{96, 28};
static constexpr COORD resized{112, 36};
static constexpr COORD fixed{80, 24};

static void check(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}

static COORD read_viewport() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    check(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info), "read viewport");
    const auto &window = info.srWindow;
    return {static_cast<SHORT>(window.Right - window.Left + 1),
            static_cast<SHORT>(window.Bottom - window.Top + 1)};
}

static void report_size(const char *label, COORD size) {
    printf("VIEWPORT-%s=%dx%d\n", label, size.X, size.Y);
    fflush(stdout);
}

static bool same_size(COORD a, COORD b) { return a.X == b.X && a.Y == b.Y; }

static volatile LONG interrupted = 0;
static BOOL WINAPI probe_control(DWORD event) {
    if (event != CTRL_C_EVENT)
        return FALSE;
    InterlockedExchange(&interrupted, 1);
    return TRUE;
}

static void screen_mouse_probe() {
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_mode = 0;
    check(GetConsoleMode(input, &original_mode), "save native input mode");
    check(SetConsoleMode(input, ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT), "enable native mouse");
    puts("SCREEN-MOUSE-READY");
    fflush(stdout);

    constexpr DWORD flags[] = {0, MOUSE_MOVED, 0, MOUSE_MOVED, MOUSE_WHEELED};
    constexpr DWORD buttons[] = {1, 1, 0, 0};
    constexpr SHORT columns[] = {9, 10, 10, 11, 11};
    size_t event = 0;
    const auto deadline = GetTickCount64() + 3000;
    while (GetTickCount64() < deadline) {
        INPUT_RECORD record{};
        DWORD count = 0;
        check(PeekConsoleInputW(input, &record, 1, &count), "peek native mouse input");
        if (!count) {
            Sleep(10);
            continue;
        }
        check(ReadConsoleInputW(input, &record, 1, &count) && count == 1, "read native mouse input");
        if (record.EventType == KEY_EVENT) {
            // The Ctrl+C test may have left a key-up event in the queue.
            check(!record.Event.KeyEvent.bKeyDown, "mouse report became a character key");
        }
        if (record.EventType != MOUSE_EVENT)
            continue;
        const auto &mouse = record.Event.MouseEvent;
        check(mouse.dwEventFlags == flags[event] && mouse.dwMousePosition.X == columns[event] &&
                  mouse.dwMousePosition.Y == 4,
              "native mouse coordinates and event flags");
        if (flags[event] == MOUSE_WHEELED)
            check(static_cast<SHORT>(HIWORD(mouse.dwButtonState)) > 0, "native wheel direction");
        else
            check(mouse.dwButtonState == buttons[event], "native mouse buttons");
        if (++event == _countof(flags)) {
            check(SetConsoleMode(input, original_mode), "restore native input mode");
            puts("SCREEN-MOUSE-DONE");
            fflush(stdout);
            return;
        }
    }
    throw std::runtime_error("timed out waiting for native mouse events");
}

static int screen_probe() {
    check(SetConsoleCtrlHandler(probe_control, TRUE), "target Ctrl+C handler");
    DWORD count = 0;
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    constexpr char ready[] = "CONTROL-READY\r\n";
    check(WriteFile(output, ready, sizeof(ready) - 1, &count, nullptr), "report Ctrl+C readiness");
    const auto deadline = GetTickCount64() + 5000;
    while (!InterlockedCompareExchange(&interrupted, 0, 0) && GetTickCount64() < deadline)
        Sleep(10);
    check(InterlockedCompareExchange(&interrupted, 0, 0) != 0, "target received Ctrl+C");
    constexpr wchar_t text[] = L"SCREEN-中文-é-Ａ\r\n";
    check(WriteConsoleW(output, text, _countof(text) - 1, &count, nullptr), "write Unicode screen");
    DWORD mode = 0;
    check(GetConsoleMode(output, &mode) &&
              SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING),
          "enable probe VT");
    constexpr char cursor[] = "CURSOR-NO\x1b[2DOK\r\n";
    check(WriteFile(output, cursor, sizeof(cursor) - 1, &count, nullptr), "write cursor move");
    screen_mouse_probe();
    return 0;
}

static BOOL WINAPI wait_control(DWORD event) { return event == CTRL_C_EVENT; }

static int outer_state(int argc, wchar_t **argv, bool failure) {
    check(argc >= 3, "outer-state target");
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD in_mode = 0, out_mode = 0;
    check(GetConsoleMode(input, &in_mode) && GetConsoleMode(output, &out_mode), "outer modes");
    out_mode &= ~ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    check(SetConsoleMode(output, out_mode) && SetConsoleCP(437) && SetConsoleOutputCP(437),
          "set outer initial state");
    check(SetConsoleCtrlHandler(wait_control, TRUE), "protect test owner from Ctrl+C");
    auto command = msys_sandbox_compat::quote(argv[2]);
    for (int i = 3; i < argc; ++i)
        command += L" " + msys_sandbox_compat::quote(argv[i]);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    check(CreateProcessW(argv[2], command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                         &startup, &child),
          "start terminal session");
    CloseHandle(child.hThread);
    const auto waited = WaitForSingleObject(child.hProcess, 25000);
    if (waited != WAIT_OBJECT_0)
        TerminateProcess(child.hProcess, 1);
    DWORD code = 1;
    GetExitCodeProcess(child.hProcess, &code);
    CloseHandle(child.hProcess);
    check(waited == WAIT_OBJECT_0 && code == (failure ? 1u : 0u), "terminal session exit");
    DWORD in_after = 0, out_after = 0;
    check(GetConsoleMode(input, &in_after) && GetConsoleMode(output, &out_after) &&
              in_after == in_mode && out_after == out_mode && GetConsoleCP() == 437 &&
              GetConsoleOutputCP() == 437,
          "restore outer modes and code pages");
    if (failure) {
        puts("OUTER-STATE-PASS");
        return 0;
    }
    CONSOLE_SCREEN_BUFFER_INFO info{};
    check(GetConsoleScreenBufferInfo(output, &info), "query outer screen");
    std::wstring screen(static_cast<size_t>(info.dwSize.X) * info.dwSize.Y, L'\0');
    DWORD count = 0;
    check(ReadConsoleOutputCharacterW(output, screen.data(), static_cast<DWORD>(screen.size()),
                                      {0, 0}, &count),
          "read rendered outer screen");
    check(screen.find(L"SCREEN-中文-é-Ａ") != std::wstring::npos, "render Unicode screen");
    check(screen.find(L"CURSOR-OK") != std::wstring::npos, "render cursor movement");
    puts("OUTER-STATE-PASS");
    return 0;
}

static int probe(bool fixed_size) {
    auto size = read_viewport();
    report_size("READY", size);
    check(same_size(size, fixed_size ? fixed : initial), "unexpected initial size");
    if (fixed_size) {
        // The driver sends Enter after resizing the outer console.
        check(getchar() == '\n', "read fixed-size checkpoint");
        const auto deadline = GetTickCount64() + 500;
        do {
            size = read_viewport();
            check(same_size(size, fixed), "fixed viewport changed");
            Sleep(10);
        } while (GetTickCount64() < deadline);
    } else {
        const auto deadline = GetTickCount64() + 5000;
        while (!same_size(size, resized) && GetTickCount64() < deadline) {
            Sleep(10);
            size = read_viewport();
        }
    }
    report_size("FINAL", size);
    check(same_size(size, fixed_size ? fixed : resized), "unexpected final size");
    return 0;
}

static int drive(int argc, wchar_t **argv, std::wstring_view mode) {
    const bool bash = mode == L"--drive-bash";
    const bool powershell = mode == L"--drive-powershell";
    const bool readline = mode == L"--drive-readline";
    const bool terminal = mode == L"--drive-terminal" || bash || powershell || readline;
    const bool resize = mode != L"--drive-stdio" && !terminal;
    const bool fixed_size = mode == L"--drive-fixed";
    const char *completion_marker = terminal ? "OUTER-STATE-PASS"
                                    : resize ? "VIEWPORT-FINAL="
                                             : "STDIO-CONSOLE";
    const DWORD expected_exit = resize || terminal ? 0 : 37;
    std::unique_ptr<void, decltype(&ClosePseudoConsole)> outer(nullptr, ClosePseudoConsole);
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    HANDLE input_read = nullptr, input_write = nullptr;
    check(CreatePipe(&input_read, &input_write, nullptr, 0), "create outer input pipe");
    Handle input(input_read, CloseHandle), send(input_write, CloseHandle);
    HANDLE output_read = nullptr, output_write = nullptr;
    check(CreatePipe(&output_read, &output_write, nullptr, 0), "create outer output pipe");
    Handle receive(output_read, CloseHandle), output(output_write, CloseHandle);
    HPCON console = nullptr;
    check(SUCCEEDED(CreatePseudoConsole(initial, input.get(), output.get(), 0, &console)),
          "create outer pseudo console");
    outer.reset(console);

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<BYTE> storage(bytes);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    check(InitializeProcThreadAttributeList(attributes, 1, 0, &bytes), "initialize attributes");
    std::unique_ptr<std::remove_pointer_t<LPPROC_THREAD_ATTRIBUTE_LIST>,
                    decltype(&DeleteProcThreadAttributeList)>
        attribute_list(attributes, DeleteProcThreadAttributeList);
    check(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console,
                                    sizeof(HPCON), nullptr, nullptr),
          "attach outer pseudo console");
    startup.lpAttributeList = attributes;

    auto command = msys_sandbox_compat::quote(argv[2]);
    for (int i = 3; i < argc; ++i)
        command += L" " + msys_sandbox_compat::quote(argv[i]);
    PROCESS_INFORMATION child{};
    check(CreateProcessW(argv[2], command.data(), nullptr, nullptr, FALSE,
                         EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo,
                         &child),
          "launch PSEC under the outer pseudo console");
    CloseHandle(child.hThread);
    Handle process(child.hProcess, CloseHandle);
    input.reset();
    output.reset();

    const auto deadline = GetTickCount64() + 25000;
    bool resize_sent = false;
    bool control_sent = false;
    bool mouse_sent = false;
    bool initialized = false, edit_sent = false, wait_sent = false, exit_sent = false;
    std::string transcript;
    auto mouse_tracking = [&] {
        const auto enabled = transcript.rfind("\x1b[?1003;1006h");
        const auto disabled = transcript.rfind("\x1b[?1003;1006l");
        return enabled != std::string::npos && (disabled == std::string::npos || enabled > disabled);
    };
    auto send_text = [&](const char *text) {
        const auto length = static_cast<DWORD>(strlen(text));
        DWORD count = 0;
        check(WriteFile(send.get(), text, length, &count, nullptr) && count == length,
              "send terminal input");
    };
    do {
        DWORD available = 0;
        while (PeekNamedPipe(receive.get(), nullptr, 0, nullptr, &available, nullptr) &&
               available) {
            char buffer[4096];
            DWORD count = 0;
            check(ReadFile(receive.get(), buffer, std::min(available, DWORD{sizeof(buffer)}),
                           &count, nullptr),
                  "read outer output");
            transcript.append(buffer, count);
            fwrite(buffer, 1, count, stdout);
        }
        if (resize && !resize_sent && transcript.find("VIEWPORT-READY=") != std::string::npos) {
            check(SUCCEEDED(ResizePseudoConsole(console, resized)), "resize outer pseudo console");
            resize_sent = true;
            if (fixed_size) {
                DWORD count = 0;
                check(WriteFile(send.get(), "\r", 1, &count, nullptr) && count == 1,
                      "send fixed-size checkpoint");
            }
        }
        if (terminal && !control_sent && transcript.find("CONTROL-READY") != std::string::npos) {
            DWORD count = 0;
            constexpr char ctrl_c[] = "\x1b[67;46;3;1;8;1_\x1b[67;46;3;0;8;1_";
            check(WriteFile(send.get(), ctrl_c, sizeof(ctrl_c) - 1, &count, nullptr) &&
                      count == sizeof(ctrl_c) - 1,
                  "send Ctrl+C to the outer terminal");
            control_sent = true;
        }
        if (bash && !initialized && transcript.find("bash-") != std::string::npos) {
            check(!mouse_tracking(), "initial Bash prompt enabled all-motion mouse tracking");
            send_text("export PS1='DEMO-READY> '; stty -echo; printf '\\nDEMO-INPUT\\n'\r");
            initialized = true;
        }
        if (!mouse_sent && transcript.find("SCREEN-MOUSE-READY") != std::string::npos) {
            check(mouse_tracking(), "native mouse mode did not reach the frontend");
            send_text("\x1b[<0;10;5M\x1b[<32;11;5M\x1b[<0;11;5m\x1b[<35;12;5M\x1b[<64;12;5M");
            mouse_sent = true;
        }
        if (mouse_sent && transcript.find("SCREEN-MOUSE-DONE") != std::string::npos)
            check(!mouse_tracking(), "native mouse mode did not turn off at the frontend");
        const auto demo_input = transcript.find("DEMO-INPUT\r\n");
        if (bash && !edit_sent && demo_input != std::string::npos &&
            transcript.find("DEMO-READY> ", demo_input) != std::string::npos) {
            check(!mouse_tracking(), "idle Bash prompt enabled all-motion mouse tracking");
            // Move left inside a quoted argument, insert X, then execute the edited line.
            send_text("printf 'EDITED=%s\\n' '中文b\x1b[DX\x1b[C'\r");
            edit_sent = true;
        }
        if (bash && !wait_sent && transcript.find("EDITED=中文Xb") != std::string::npos) {
            send_text(
                "printf 'SCREEN-中文-é-Ａ\\n'; printf 'CURSOR-NO\\033[2DOK\\n'; "
                "test \"$(stty size)\" = '28 96' || exit 82; "
                "perl -e '$SIG{INT}=sub {exit 130}; $|=1; print \"CONTROL-READY\\n\"; sleep 30'\r");
            wait_sent = true;
        }
        if (bash && control_sent && !exit_sent &&
            transcript.rfind("DEMO-READY> ") > transcript.find("CONTROL-READY") &&
            transcript.rfind("DEMO-READY> ") != std::string::npos) {
            send_text("s=$?; test \"$s\" = 130 || exit 83; echo DEMO-CTRL-C-PASS; exit 0\r");
            exit_sent = true;
        }
        if (powershell && !initialized &&
            transcript.find("DEMO-PS-READY\r\n") != std::string::npos) {
            send_text("中文-é-Ａ\r");
            initialized = true;
        }
        if (readline && !initialized && transcript.find("PS ") != std::string::npos &&
            transcript.find("> ") != std::string::npos) {
            const auto command_text =
                "Write-Host 'HISTORY-CHECK-" + std::to_string(GetTickCount64()) +
                "'; Write-Host 'SCREEN-中文-é-Ａ'; [Console]::Write(\"CURSOR-NO\" + "
                "[char]27 + \"[2DOK\" + [Environment]::NewLine); exit 0\r";
            send_text(command_text.c_str());
            initialized = true;
        }
        DWORD code = 0;
        check(GetExitCodeProcess(process.get(), &code), "get PSEC exit code");
        if (code != STILL_ACTIVE &&
            (code != expected_exit || transcript.find(completion_marker) != std::string::npos))
            return static_cast<int>(code);
        Sleep(10);
    } while (GetTickCount64() < deadline);
    TerminateProcess(process.get(), 1);
    throw std::runtime_error("outer pseudo console timed out");
}

int wmain(int argc, wchar_t **argv) try {
    check(argc >= 2, "select a test mode");
    const std::wstring_view mode(argv[1]);
    if (mode == L"--screen-probe")
        return screen_probe();
    if (mode == L"--outer-state" || mode == L"--outer-failure")
        return outer_state(argc, argv, mode == L"--outer-failure");
    if (mode == L"--probe" || mode == L"--probe-fixed")
        return probe(mode == L"--probe-fixed");
    check(argc >= 3 &&
              (mode == L"--drive" || mode == L"--drive-fixed" || mode == L"--drive-stdio" ||
               mode == L"--drive-terminal" || mode == L"--drive-bash" ||
               mode == L"--drive-powershell" || mode == L"--drive-readline"),
          "select a driver mode");
    return drive(argc, argv, mode);
} catch (const std::exception &error) {
    fprintf(stderr, "conpty-resize: %s (Win32 %lu)\n", error.what(), GetLastError());
    return 1;
}
