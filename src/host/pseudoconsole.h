#pragma once
#include "conpty_input.h"
#include "stream_write.h"
#include <windows.h>
#include <winternl.h>
#include <string>
#include <string_view>
#include <thread>
#include <stdexcept>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <climits>

// The default path creates ConPTY in PSEC and connects a native session host.
// That host owns the initial console handles and passes explicit stdio to MSYS.
// Readers drain output independently of input and session teardown.
class Pseudoconsole {
    std::thread resizer;
    HANDLE resize_stop = nullptr;
    std::atomic<DWORD> output_error_code{ERROR_SUCCESS};

    static COORD viewport_size(const CONSOLE_SCREEN_BUFFER_INFO &info) {
        const auto width = info.srWindow.Right - info.srWindow.Left + 1;
        const auto height = info.srWindow.Bottom - info.srWindow.Top + 1;
        if (width <= 0 || width > SHRT_MAX || height <= 0 || height > SHRT_MAX)
            return {};
        return {static_cast<SHORT>(width), static_cast<SHORT>(height)};
    }

  public:
    static constexpr ULONG_PTR output_failure_key = 1;

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
    DWORD output_error() const { return output_error_code.load(); }

    void create(HANDLE completion, HANDLE input, HANDLE output, const std::wstring &script,
                COORD dimensions = {100, 30},
                bool follow_viewport = false) {
        input_source = input;
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
        }
        COORD cursor{};
        if (GetConsoleMode(output, &original_output_mode)) {
            restore_output_mode = true;
            original_output_cp = GetConsoleOutputCP();
            const auto mode =
                original_output_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode(output, mode) || !original_output_cp ||
                !SetConsoleOutputCP(CP_UTF8))
                throw std::runtime_error("configure ConPTY terminal output");
            SetConsoleMode(output, mode | DISABLE_NEWLINE_AUTO_RETURN);
            CONSOLE_SCREEN_BUFFER_INFO info{};
            if (GetConsoleScreenBufferInfo(output, &info)) {
                if (follow_viewport && restore_input_mode)
                    viewport = viewport_size(info);
                const auto size = viewport.X ? viewport : dimensions;
                const auto column = info.dwCursorPosition.X - info.srWindow.Left + 1;
                const auto row = info.dwCursorPosition.Y - info.srWindow.Top + 1;
                if (column > 0 && row > 0 && column <= size.X && row <= size.Y &&
                    info.dwCursorPosition.X <= info.srWindow.Right &&
                    info.dwCursorPosition.Y <= info.srWindow.Bottom)
                    cursor = {static_cast<SHORT>(column), static_cast<SHORT>(row)};
            }
        }
        if (viewport.X)
            dimensions = viewport;
        if (!CreatePipe(&input_read, &input_write, nullptr, 0) ||
            !CreatePipe(&output_read, &output_write, nullptr, 0))
            throw std::runtime_error("ConPTY pipes");
        // A cursor-inheriting ConPTY can ask for a reply during startup.
        reader = std::thread([this, completion, cursor] {
            constexpr std::string_view request = "\x1b[6n";
            char buffer[8192 + request.size() - 1];
            bool awaiting_cursor = cursor.X != 0;
            DWORD held = 0, count = 0;
            bool forwarding = true;
            const auto forward = [&](std::string_view bytes) {
                if (forwarding && !msys_sandbox_compat::write_all(
                                      output_sink, bytes.data(), static_cast<DWORD>(bytes.size()))) {
                    output_error_code = GetLastError();
                    PostQueuedCompletionStatus(completion, 0, output_failure_key, nullptr);
                    // Keep draining while the session host tears down the job and ConPTY.
                    forwarding = false;
                }
            };
            while (ReadFile(output_read, buffer + held, 8192, &count, nullptr) && count) {
                std::string_view bytes(buffer, held + count);
                if (awaiting_cursor) {
                    // Answer the startup cursor query on our own pipes. The outer console
                    // supplies the position even when keyboard input is redirected.
                    const auto match = bytes.find(request);
                    if (match != std::string_view::npos) {
                        char reply[16];
                        const auto length = snprintf(reply, sizeof(reply), "\x1b[%d;%dR", cursor.Y,
                                                     cursor.X);
                        msys_sandbox_compat::write_all(input_write, reply, static_cast<DWORD>(length));
                        forward(bytes.substr(0, match));
                        bytes.remove_prefix(match + request.size());
                        awaiting_cursor = false;
                        held = 0;
                    } else {
                        // ReadFile can split the four-byte query across reads.
                        held = static_cast<DWORD>(std::min(bytes.size(), request.size() - 1));
                        while (held && bytes.substr(bytes.size() - held) != request.substr(0, held))
                            --held;
                        bytes.remove_suffix(held);
                    }
                }
                forward(bytes);
                if (held)
                    memmove(buffer, bytes.data() + bytes.size(), held);
            }
            forward(std::string_view(buffer, held));
        });
        const auto flags = cursor.X ? PSEUDOCONSOLE_INHERIT_CURSOR : 0;
        const auto result = CreatePseudoConsole(dimensions, input_read, output_write, flags, &handle);
        if (FAILED(result)) {
            char detail[64];
            snprintf(detail, sizeof(detail), "CreatePseudoConsole: HRESULT %08lx",
                     static_cast<ULONG>(result));
            throw std::runtime_error(detail);
        }
        writer = std::thread([this] {
            msys_sandbox_compat::ConptyInput terminal_input;
            char buffer[4096];
            DWORD count = 0;
            while (!stopping && ReadFile(input_source, buffer, sizeof(buffer), &count, nullptr) &&
                   count) {
                std::string_view bytes(buffer, count);
                if (restore_input_mode)
                    bytes = terminal_input.translate(bytes);
                if (!msys_sandbox_compat::write_all(input_write, bytes.data(),
                                                     static_cast<DWORD>(bytes.size())))
                    return;
            }
            const auto tail = terminal_input.remainder();
            if (!stopping && !tail.empty())
                msys_sandbox_compat::write_all(input_write, tail.data(),
                                               static_cast<DWORD>(tail.size()));
            // Source EOF ends this pump. Closing the VT input pipe requests
            // console shutdown while attached clients may still be running.
        });
        if (viewport.X) {
            // Sample independently of VT reads so an idle terminal still resizes.
            resize_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!resize_stop)
                throw std::runtime_error("create ConPTY resize stop event");
            resizer = std::thread([this, output, viewport] {
                auto applied = viewport;
                while (WaitForSingleObject(resize_stop, 20) == WAIT_TIMEOUT && !stopping) {
                    CONSOLE_SCREEN_BUFFER_INFO info{};
                    if (!GetConsoleScreenBufferInfo(output, &info))
                        continue;
                    const auto current = viewport_size(info);
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
    void close() {
        if (stopping.exchange(true))
            return;
        if (resize_stop)
            SetEvent(resize_stop);
        if (resizer.joinable())
            resizer.join();
        if (resize_stop)
            CloseHandle(resize_stop);
        if (writer.joinable()) {
            do {
                CancelSynchronousIo(writer.native_handle());
            } while (WaitForSingleObject(writer.native_handle(), 20) == WAIT_TIMEOUT);
            writer.join();
        }
        if (owns_input)
            CloseHandle(input_source);
        if (handle)
            ClosePseudoConsole(handle);
        connected();
        if (reader.joinable())
            reader.join();
        // The reader can still answer the startup query while ConPTY closes.
        if (input_write)
            CloseHandle(input_write);
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

    ~Pseudoconsole() { close(); }
};
