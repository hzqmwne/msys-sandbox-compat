#pragma once
#include "conpty_input.h"
#include "stream_write.h"
#include <windows.h>
#include <winternl.h>
#include <string>
#include <thread>
#include <stdexcept>
#include <cstdio>
#include <atomic>
#include <climits>

// The default path creates ConPTY in PSEC and connects a native session host.
// That host owns the initial console handles and passes explicit stdio to MSYS.
// Readers drain output independently of input and session teardown.
class Pseudoconsole {
    std::thread resizer;

    static COORD viewport_size(HANDLE output) {
        CONSOLE_SCREEN_BUFFER_INFO info{};
        if (!GetConsoleScreenBufferInfo(output, &info))
            return {};
        const auto width = info.srWindow.Right - info.srWindow.Left + 1;
        const auto height = info.srWindow.Bottom - info.srWindow.Top + 1;
        if (width <= 0 || width > SHRT_MAX || height <= 0 || height > SHRT_MAX)
            return {};
        return {static_cast<SHORT>(width), static_cast<SHORT>(height)};
    }

  public:
    HPCON handle = nullptr;
    HANDLE input_read = nullptr, input_write = nullptr;
    HANDLE output_read = nullptr, output_write = nullptr;
    std::thread reader, writer;
    std::atomic<bool> stopping{false};
    DWORD original_input_mode = 0;
    DWORD original_output_mode = 0;
    UINT original_input_cp = 0, original_output_cp = 0;
    bool restore_input_mode = false;
    bool restore_output_mode = false;
    HANDLE output_sink = nullptr;
    HANDLE input_source = nullptr;
    bool owns_input = false;
    void create(const std::wstring &script, COORD dimensions = {100, 30},
                bool follow_viewport = false) {
        input_source = GetStdHandle(STD_INPUT_HANDLE);
        const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        output_sink = output;
        COORD viewport{};
        if (!script.empty()) {
            input_source = CreateFileW(script.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (input_source == INVALID_HANDLE_VALUE)
                throw std::runtime_error("open ConPTY input script");
            owns_input = true;
        } else if (GetConsoleMode(input_source, &original_input_mode)) {
            restore_input_mode = true;
            original_input_cp = GetConsoleCP();
            // Disabling Quick Edit while keeping ENABLE_MOUSE_INPUT asks the outer
            // terminal for mouse reports even when the inner application did not.
            const auto mode = (original_input_mode &
                               ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT |
                                 ENABLE_QUICK_EDIT_MODE | ENABLE_MOUSE_INPUT)) |
                              ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT;
            if (!SetConsoleMode(input_source, mode) || !original_input_cp ||
                !SetConsoleCP(CP_UTF8))
                throw std::runtime_error("configure ConPTY terminal input");
            if (follow_viewport)
                viewport = viewport_size(output);
        }
        if (GetConsoleMode(output, &original_output_mode)) {
            restore_output_mode = true;
            original_output_cp = GetConsoleOutputCP();
            const auto mode =
                original_output_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode(output, mode) || !original_output_cp ||
                !SetConsoleOutputCP(CP_UTF8))
                throw std::runtime_error("configure ConPTY terminal output");
            SetConsoleMode(output, mode | DISABLE_NEWLINE_AUTO_RETURN);
        }
        if (viewport.X)
            dimensions = viewport;
        if (!CreatePipe(&input_read, &input_write, nullptr, 0) ||
            !CreatePipe(&output_read, &output_write, nullptr, 0))
            throw std::runtime_error("ConPTY pipes");
        auto result = CreatePseudoConsole(dimensions, input_read, output_write, 0, &handle);
        if (FAILED(result)) {
            fprintf(stderr, "CreatePseudoConsole HRESULT=%08lx\n", static_cast<ULONG>(result));
            throw std::runtime_error("CreatePseudoConsole");
        }
        reader = std::thread([this] {
            char buffer[8192];
            DWORD count = 0;
            while (ReadFile(output_read, buffer, sizeof(buffer), &count, nullptr) && count) {
                if (!msys_sandbox_compat::write_all(GetStdHandle(STD_OUTPUT_HANDLE), buffer, count))
                    break;
            }
        });
        writer = std::thread([this] {
            msys_sandbox_compat::ConptyInput terminal_input;
            char buffer[4096];
            DWORD count = 0;
            while (!stopping && ReadFile(input_source, buffer, sizeof(buffer), &count, nullptr) &&
                   count) {
                std::string_view bytes(buffer, count);
                std::string translated;
                if (restore_input_mode) {
                    translated = terminal_input.translate(bytes);
                    bytes = translated;
                }
                if (!msys_sandbox_compat::write_all(input_write, bytes.data(),
                                                     static_cast<DWORD>(bytes.size())))
                    return;
            }
            const auto tail = terminal_input.remainder();
            if (!stopping && !tail.empty())
                msys_sandbox_compat::write_all(input_write, tail.data(),
                                               static_cast<DWORD>(tail.size()));
        });
        if (viewport.X) {
            // Sample independently of VT reads so an idle terminal still resizes.
            resizer = std::thread([this, output, viewport] {
                auto applied = viewport;
                while (!stopping) {
                    Sleep(20);
                    if (stopping)
                        break;
                    const auto current = viewport_size(output);
                    if (current.X && (current.X != applied.X || current.Y != applied.Y) &&
                        SUCCEEDED(ResizePseudoConsole(handle, current)))
                        applied = current;
                }
            });
        }
    }
    void connected() {
        if (input_read) {
            CloseHandle(input_read);
            input_read = nullptr;
        }
        if (output_write) {
            CloseHandle(output_write);
            output_write = nullptr;
        }
    }
    ~Pseudoconsole() {
        stopping = true;
        if (resizer.joinable())
            resizer.join();
        if (writer.joinable()) {
            do {
                CancelSynchronousIo(writer.native_handle());
            } while (WaitForSingleObject(writer.native_handle(), 20) == WAIT_TIMEOUT);
            writer.join();
        }
        if (owns_input)
            CloseHandle(input_source);
        if (input_write)
            CloseHandle(input_write);
        if (handle)
            ClosePseudoConsole(handle);
        connected();
        if (reader.joinable())
            reader.join();
        if (restore_input_mode)
            SetConsoleMode(input_source, original_input_mode);
        if (restore_output_mode)
            SetConsoleMode(output_sink, original_output_mode);
        if (original_input_cp)
            SetConsoleCP(original_input_cp);
        if (original_output_cp)
            SetConsoleOutputCP(original_output_cp);
        if (output_read)
            CloseHandle(output_read);
    }
};
