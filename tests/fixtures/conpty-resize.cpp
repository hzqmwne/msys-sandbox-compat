#include "msys_sandbox_compat/command_line.h"
#include <windows.h>
#include <algorithm>
#include <cstdio>
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
    const bool resize = mode != L"--drive-stdio";
    const bool fixed_size = mode == L"--drive-fixed";
    const char *completion_marker = resize ? "VIEWPORT-FINAL=" : "STDIO-CONSOLE";
    const DWORD expected_exit = resize ? 0 : 37;
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

    const auto deadline = GetTickCount64() + 15000;
    bool resize_sent = false;
    std::string transcript;
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
    if (mode == L"--probe" || mode == L"--probe-fixed")
        return probe(mode == L"--probe-fixed");
    check(argc >= 3 && (mode == L"--drive" || mode == L"--drive-fixed" || mode == L"--drive-stdio"),
          "select a driver mode");
    return drive(argc, argv, mode);
} catch (const std::exception &error) {
    fprintf(stderr, "conpty-resize: %s (Win32 %lu)\n", error.what(), GetLastError());
    return 1;
}
