#pragma once
#include "host.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cwchar>
#include <stdexcept>
#include <string_view>

namespace msys_sandbox_compat {
using StandardHandles = std::array<HANDLE, 3>;
using ConsoleStreams = std::array<bool, 3>;
inline constexpr wchar_t session_stdio_option[] = L"--internal-conpty-session";

inline bool console_handle(HANDLE handle) {
    DWORD mode = 0;
    return GetConsoleMode(handle, &mode) != FALSE;
}

inline bool valid_handle(HANDLE handle) { return handle && handle != INVALID_HANDLE_VALUE; }

class ConsoleEndpoints {
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    Handle opened_input{nullptr, CloseHandle};
    Handle opened_output{nullptr, CloseHandle};

    static HANDLE open_device(const wchar_t *name) {
        HANDLE handle = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                   nullptr);
        return handle == INVALID_HANDLE_VALUE ? nullptr : handle;
    }

  public:
    HANDLE input = nullptr;
    HANDLE output = nullptr;

    bool open(const StandardHandles &stdio, const ConsoleStreams &console) {
        if (!std::any_of(console.begin(), console.end(), [](bool stream) { return stream; }) ||
            !GetConsoleCP())
            return false;

        input = stdio[0];
        output = console[1] ? stdio[1] : stdio[2];
        if (!console[0]) {
            opened_input.reset(open_device(L"CONIN$"));
            input = opened_input.get();
        }
        if (!console[1] && !console[2]) {
            opened_output.reset(open_device(L"CONOUT$"));
            output = opened_output.get();
        }
        return input && output;
    }
};

// Only the redirected handles cross into the native session owner. Let Windows
// create all three of its own console handles so it can retain them as clients exit.
class SessionStdio {
    StandardHandles owned{};
    size_t count = 0;

  public:
    SessionStdio() = default;
    SessionStdio(const SessionStdio &) = delete;
    SessionStdio &operator=(const SessionStdio &) = delete;
    ~SessionStdio() { close(); }

    void close() {
        while (count)
            CloseHandle(owned[--count]);
    }

    std::wstring prepare(const StandardHandles &stdio, const ConsoleStreams &console) {
        StandardHandles forwarded{};
        std::wstring arguments = std::wstring(L" ") + session_stdio_option;
        for (size_t i = 0; i < stdio.size(); ++i) {
            if (console[i]) {
                arguments += L" console";
                continue;
            }
            forwarded[i] = stdio[i];
            if (valid_handle(stdio[i])) {
                const auto previous = std::find(stdio.begin(), stdio.begin() + i, stdio[i]);
                if (previous != stdio.begin() + i) {
                    forwarded[i] = forwarded[previous - stdio.begin()];
                } else {
                    HANDLE self = GetCurrentProcess();
                    check(DuplicateHandle(self, stdio[i], self, &forwarded[i], 0, TRUE,
                                          DUPLICATE_SAME_ACCESS), "duplicate redirected stdio");
                    owned[count++] = forwarded[i];
                }
            }
            arguments += L" " + std::to_wstring(reinterpret_cast<ULONG_PTR>(forwarded[i]));
        }
        return arguments;
    }

    void receive(wchar_t *const *arguments, StandardHandles &stdio) {
        for (size_t i = 0; i < stdio.size(); ++i) {
            const std::wstring_view argument = arguments[i];
            if (argument == L"console")
                continue;

            wchar_t *end = nullptr;
            errno = 0;
            const auto value = std::wcstoull(argument.data(), &end, 10);
            if (argument.empty() || argument.front() < L'0' || argument.front() > L'9' ||
                errno == ERANGE || *end)
                throw std::runtime_error("invalid console session stdio handle");
            HANDLE handle = reinterpret_cast<HANDLE>(value);
            if (valid_handle(handle) && std::find(owned.begin(), owned.begin() + count, handle) ==
                                            owned.begin() + count) {
                DWORD flags = 0;
                if (!GetHandleInformation(handle, &flags) || !(flags & HANDLE_FLAG_INHERIT) ||
                    console_handle(handle))
                    throw std::runtime_error("invalid inherited console session stdio handle");
                owned[count++] = handle;
            }
            stdio[i] = handle;
        }
    }

    bool has_handles() const { return count != 0; }

    void set_inheritance_list(LPPROC_THREAD_ATTRIBUTE_LIST attributes) {
        check(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                        owned.data(), count * sizeof(HANDLE), nullptr, nullptr),
              "redirected stdio inheritance list");
    }
};
} // namespace msys_sandbox_compat
