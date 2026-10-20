#pragma once
#include <windows.h>
#include <winternl.h>
#include <fstream>
#include <string>
#include <thread>
#include <stdexcept>
#include <cstdio>
#include <filesystem>
#include <atomic>

// The default path creates ConPTY in PSEC and connects a native session host.
// That host owns the initial console handles and passes explicit stdio to MSYS.
// Readers drain output independently of input and session teardown.
class Pseudoconsole {
  public:
    HPCON handle = nullptr;
    HANDLE input_read = nullptr, input_write = nullptr;
    HANDLE output_read = nullptr, output_write = nullptr;
    std::thread reader, writer;
    std::atomic<bool> stopping{false};
    DWORD original_input_mode = 0;
    bool restore_input_mode = false;
    void create(const std::wstring &script, COORD dimensions = {100, 30}) {
        if (!script.empty()) {
            std::ifstream input{std::filesystem::path(script), std::ios::binary};
            if (!input.good())
                throw std::runtime_error("open ConPTY input script");
        } else if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &original_input_mode)) {
            restore_input_mode =
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),
                               (original_input_mode &
                                ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) |
                                   ENABLE_VIRTUAL_TERMINAL_INPUT) != FALSE;
        }
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
            DWORD count = 0, written = 0;
            while (ReadFile(output_read, buffer, sizeof(buffer), &count, nullptr) && count) {
                if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, count, &written, nullptr))
                    break;
            }
        });
        writer = std::thread([this, script] {
            char buffer[4096];
            DWORD count = 0;
            if (!script.empty()) {
                std::ifstream file{std::filesystem::path(script), std::ios::binary};
                while (!stopping && (file.read(buffer, sizeof(buffer)) || file.gcount())) {
                    if (!WriteFile(input_write, buffer, static_cast<DWORD>(file.gcount()), &count,
                                   nullptr))
                        break;
                }
            } else {
                while (!stopping &&
                       ReadFile(GetStdHandle(STD_INPUT_HANDLE), buffer, sizeof(buffer), &count,
                                nullptr) &&
                       count) {
                    DWORD written = 0;
                    if (!WriteFile(input_write, buffer, count, &written, nullptr))
                        break;
                }
            }
        });
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
        if (writer.joinable()) {
            do {
                CancelSynchronousIo(writer.native_handle());
            } while (WaitForSingleObject(writer.native_handle(), 20) == WAIT_TIMEOUT);
            writer.join();
        }
        if (restore_input_mode)
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), original_input_mode);
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
