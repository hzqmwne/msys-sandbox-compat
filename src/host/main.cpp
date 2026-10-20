#include "host.h"
#include "msys_compat/injector.h"
#include <cstdio>
#include <stdexcept>
#include "pseudoconsole.h"

using namespace msys_compat;
namespace fs = std::filesystem;

int wmain(int argc, wchar_t **argv) try {
    bool trace = false;
    bool conpty = false;
    std::wstring input_script;
    COORD terminal_size{100, 30};
    fs::path runtime = L"C:\\Program Files\\Git\\usr\\bin\\msys-2.0.dll";
    int first = 1;
    while (first < argc) {
        std::wstring option = argv[first];
        if (option == L"--trace") {
            trace = true;
            ++first;
        } else if (option == L"--conpty") {
            conpty = true;
            ++first;
        } else if (option == L"--conpty-script" && first + 1 < argc) {
            conpty = true;
            input_script = argv[first + 1];
            first += 2;
        } else if (option == L"--conpty-size" && first + 1 < argc) {
            unsigned width = 0, height = 0;
            wchar_t extra = 0;
            check(swscanf_s(argv[first + 1], L"%ux%u%c", &width, &height, &extra, 1) == 2 &&
                      width > 0 && width <= 32767 && height > 0 && height <= 32767,
                  "terminal size WIDTHxHEIGHT");
            terminal_size = {static_cast<SHORT>(width), static_cast<SHORT>(height)};
            first += 2;
        } else if (option == L"--runtime" && first + 1 < argc) {
            runtime = fs::absolute(argv[first + 1]);
            first += 2;
        } else
            break;
    }
    if (first == argc) {
        fprintf(
            stderr,
            "Usage (inside a restricted context): msys-compat [--trace] [--runtime DLL] PROGRAM "
            "[arguments...]\n");
        return 2;
    }
    auto executable = fs::absolute(argv[first]);
    auto state = std::make_unique<AgentState>();
    state->trace = trace;
    state->api = resolve_api();
    configure_runtime_paths(runtime, *state);
    std::unique_ptr<void, decltype(&CloseHandle)> object_directory(configure_security(*state),
                                                                   CloseHandle);
    Pseudoconsole pty;
    std::vector<BYTE> attribute_buffer;
    if (conpty)
        pty.create(input_script, terminal_size);
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    check(job != nullptr, "create process-tree job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "configure job");
    HANDLE completion = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    check(completion != nullptr, "create job completion port");
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT association{job, completion};
    check(SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &association,
                                  sizeof(association)),
          "associate job completion");
    auto command = quote(executable.wstring());
    for (int index = first + 1; index < argc; ++index)
        command += L" " + quote(argv[index]);
    if (conpty) {
        // Let a native session host own the console's automatically created
        // handles. It starts the target with explicit inherited stdio, so
        // MSYS may close its own copies without FreeConsole later closing
        // recycled handle values from KernelBase's console state.
        wchar_t own_path[32768];
        check(GetModuleFileNameW(nullptr, own_path, _countof(own_path)) != 0,
              "locate console session host");
        executable = own_path;
        command = quote(executable.wstring()) + L" --runtime " + quote(runtime.wstring()) +
                  (trace ? L" --trace " : L" ") + command;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = conpty ? sizeof(startup) : sizeof(STARTUPINFOW);
    if (conpty) {
        // Explicit null std handles suppress Windows' legacy duplication of
        // the redirected parent's stdio. Console initialization then creates
        // handles for the requested pseudoconsole.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        attribute_buffer.resize(bytes);
        startup.lpAttributeList =
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_buffer.data());
        check(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes),
              "ConPTY attribute list");
        check(UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pty.handle,
                                        sizeof(HPCON), nullptr, nullptr),
              "ConPTY attribute");
    } else {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }
    PROCESS_INFORMATION child{};
    check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, !conpty,
                         CREATE_SUSPENDED | (conpty ? EXTENDED_STARTUPINFO_PRESENT : 0), nullptr,
                         nullptr, &startup.StartupInfo, &child),
          "create suspended root");
    if (conpty) {
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        pty.connected();
    }
    try {
        check(AssignProcessToJobObject(job, child.hProcess), "assign tree job");
        ProcessImage image{};
        check_nt(identify_process(state->api, child.hProcess, state->runtime, image),
                 "classify actual root image");
        if (image.related) {
            // A cold MSYS start needs a real primary-token handle. A token
            // inherited through an MSYS-created native bridge may deny this,
            // even though our own read-only pseudo-token queries succeeded.
            HANDLE root_token = nullptr;
            check(OpenProcessToken(child.hProcess, TOKEN_QUERY, &root_token),
                  "query MSYS root token before initialization");
            CloseHandle(root_token);
            auto directory = std::wstring(image.path);
            directory.resize(directory.rfind(L'\\') + 1);
            memcpy(state->application_directory, directory.c_str(), (directory.size() + 1) * 2);
            wchar_t own_path[32768];
            check(GetModuleFileNameW(nullptr, own_path, _countof(own_path)) != 0, "locate agent");
            inject_root(child.hProcess, child.hThread, image, *state,
                        fs::path(own_path).parent_path() / L"msys-compat.dll");
        }
        fprintf(stderr,
                "[launcher] pid=%lu classification=live-imports root=%s hooks=%zu debugger=none\n",
                child.dwProcessId, image.related ? "msys" : "native",
                image.related ? hook_count : 0);
        check(::ResumeThread(child.hThread) != static_cast<DWORD>(-1), "resume root");
        CloseHandle(child.hThread);
        child.hThread = nullptr;
        DWORD message = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED overlapped = nullptr;
        do {
            check(GetQueuedCompletionStatus(completion, &message, &key, &overlapped, INFINITE),
                  "wait process tree");
        } while (message != JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO);
        DWORD result = 1;
        check(GetExitCodeProcess(child.hProcess, &result), "root exit code");
        fprintf(stderr, "[summary] exit=%lu\n", result);
        CloseHandle(child.hProcess);
        CloseHandle(completion);
        CloseHandle(job);
        return static_cast<int>(result);
    } catch (...) {
        ::TerminateProcess(child.hProcess, 1);
        CloseHandle(job);
        if (child.hThread)
            CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        CloseHandle(completion);
        throw;
    }
} catch (const std::exception &error) {
    fprintf(stderr, "[fatal] %s\n", error.what());
    return 1;
}
