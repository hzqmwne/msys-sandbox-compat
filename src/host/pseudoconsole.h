#pragma once
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
    bool restore_input_mode = false;
    HANDLE input_source = nullptr;
    bool owns_input = false;
    void create(const std::wstring &script, COORD dimensions = {100, 30},
                bool follow_viewport = false) {
        input_source = GetStdHandle(STD_INPUT_HANDLE);
        const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD viewport{};
        if (!script.empty()) {
            input_source = CreateFileW(script.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (input_source == INVALID_HANDLE_VALUE)
                throw std::runtime_error("open ConPTY input script");
            owns_input = true;
        } else if (GetConsoleMode(input_source, &original_input_mode)) {
            restore_input_mode =
                SetConsoleMode(input_source,
                               (original_input_mode &
                                ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) |
                                   ENABLE_VIRTUAL_TERMINAL_INPUT) != FALSE;
            if (follow_viewport)
                viewport = viewport_size(output);
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
            char buffer[4096];
            DWORD count = 0;
            while (!stopping && ReadFile(input_source, buffer, sizeof(buffer), &count, nullptr) &&
                   count) {
                if (!msys_sandbox_compat::write_all(input_write, buffer, count))
                    break;
            }
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
        if (restore_input_mode)
            SetConsoleMode(input_source, original_input_mode);
        if (owns_input)
            CloseHandle(input_source);
        if (input_write)
            CloseHandle(input_write);
        if (handle)
            ClosePseudoConsole(handle);
        connected();
        if (reader.joinable())
            reader.join();
        if (output_read)
            CloseHandle(output_read);
    }
};
