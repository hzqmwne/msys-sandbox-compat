#include "host.h"
#include "msys_sandbox_compat/agent.h"
#include <bitset>
#include <cstdio>
#include <stdexcept>
#include "pseudoconsole.h"

using namespace msys_sandbox_compat;
namespace fs = std::filesystem;

namespace {
constexpr struct {
    const wchar_t *name;
    Module module;
} module_options[] = {
    {L"propagation", Module::propagation},        {L"heap-window", Module::heap_window},
    {L"exe-placement", Module::exe_placement},  {L"dll-placement", Module::dll_placement},
    {L"ipc", Module::ipc},                       {L"process-dacl", Module::process_dacl},
    {L"token-dacl", Module::token_dacl},
};

uint32_t module_option(const std::wstring &name) {
    for (const auto &option : module_options)
        if (name == option.name)
            return bit(option.module);
    throw std::runtime_error("unknown compatibility module");
}
} // namespace

static BOOL WINAPI wait_control(DWORD event) { return event == CTRL_C_EVENT; }

static bool has_console_stdio() {
    DWORD mode = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) &&
           GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) &&
           GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode);
}

int wmain(int argc, wchar_t **argv) try {
    bool trace = false;
    bool force_conpty = false;
    bool disable_conpty = false;
    bool fixed_terminal_size = false;
    bool native_relay = false;
    uint32_t disabled_modules = 0;
    std::wstring input_script;
    COORD terminal_size{100, 30};
    int first = 1;
    while (first < argc) {
        std::wstring option = argv[first];
        if (option == L"--trace") {
            trace = true;
            ++first;
        } else if (option == L"--native-relay") {
            native_relay = true;
            ++first;
        } else if (option == L"--disable-module") {
            if (first + 1 >= argc)
                throw std::runtime_error("--disable-module requires a module name");
            disabled_modules |= module_option(argv[first + 1]);
            first += 2;
        } else if (option == L"--conpty") {
            force_conpty = true;
            ++first;
        } else if (option == L"--no-conpty") {
            disable_conpty = true;
            ++first;
        } else if (option == L"--conpty-script" && first + 1 < argc) {
            force_conpty = true;
            input_script = argv[first + 1];
            first += 2;
        } else if (option == L"--conpty-size" && first + 1 < argc) {
            unsigned width = 0, height = 0;
            wchar_t extra = 0;
            check(swscanf_s(argv[first + 1], L"%ux%u%c", &width, &height, &extra, 1) == 2 &&
                      width > 0 && width <= 32767 && height > 0 && height <= 32767,
                  "terminal size WIDTHxHEIGHT");
            terminal_size = {static_cast<SHORT>(width), static_cast<SHORT>(height)};
            fixed_terminal_size = true;
            first += 2;
        } else if (option == L"--runtime" && first + 1 < argc) {
            // Retain the old spelling for existing launch commands.
            first += 2;
        } else
            break;
    }
    if (first == argc) {
        fprintf(stderr, "Usage (inside a restricted context): msys-sandbox-compat [--trace] "
                        "[--native-relay] [--disable-module NAME] [--runtime DLL] PROGRAM "
                        "[arguments...]\n"
                        "Terminal options (before PROGRAM): "
                        "[--conpty | --no-conpty | --conpty-script FILE] "
                        "[--conpty-size WIDTHxHEIGHT]\n");
        return 2;
    }
    if (force_conpty && disable_conpty)
        throw std::runtime_error("--no-conpty conflicts with --conpty or --conpty-script");
    if (native_relay && (disabled_modules & bit(Module::propagation)))
        throw std::runtime_error("--native-relay requires the propagation module");
    const bool conpty = force_conpty || (!disable_conpty && has_console_stdio());
    check(SetConsoleCtrlHandler(wait_control, TRUE), "register waiting-host Ctrl+C handler");
    auto executable = fs::absolute(argv[first]);
    std::unique_ptr<AgentState> state;
    auto inherited = inherited_agent();
    std::wstring session_tag;
    std::unique_ptr<void, decltype(&CloseHandle)> object_directory(nullptr, CloseHandle);
    if (inherited) {
        if (disabled_modules & ~inherited->disabled_modules)
            throw std::runtime_error("module options conflict with inherited relay");
        disabled_modules = inherited->disabled_modules;
        if (trace)
            inherited->trace = 1;
        trace = inherited->trace != 0;
        native_relay = true;
    } else {
        state = std::make_unique<AgentState>();
        state->trace = trace;
        state->native_relay = native_relay;
        state->disabled_modules = disabled_modules;
        session_tag = require_restricted_context(state->enabled(Module::ipc));
        if (state->modules())
            state->api = resolve_api(*state);
    }
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    Handle job(CreateJobObjectW(nullptr, nullptr), CloseHandle);
    check(job != nullptr, "create process-tree job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "configure job");
    Handle completion(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1), CloseHandle);
    check(completion != nullptr, "create job completion port");
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT association{job.get(), completion.get()};
    check(SetInformationJobObject(job.get(), JobObjectAssociateCompletionPortInformation, &association,
                                  sizeof(association)),
          "associate job completion");
    Pseudoconsole pty;
    std::vector<BYTE> attribute_buffer;
    if (conpty)
        pty.create(completion.get(), input_script, terminal_size, !fixed_terminal_size);
    auto check_conpty_output = [&] {
        if (const auto error = pty.output_error()) {
            SetLastError(error);
            check(false, "forward ConPTY output");
        }
    };
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
        auto session_command = quote(executable.wstring()) + L" --no-conpty";
        if (native_relay)
            session_command += L" --native-relay";
        if (trace)
            session_command += L" --trace";
        for (const auto &option : module_options)
            if (disabled_modules & bit(option.module))
                session_command += std::wstring(L" --disable-module ") + option.name;
        command = session_command + L" " + command;
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
    bool reserved = false;
    check(create_root(executable.c_str(), command.data(), startup, conpty, state.get(), child,
                      reserved),
          "create suspended root");
    if (conpty) {
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        pty.connected();
    }
    try {
        check(AssignProcessToJobObject(job.get(), child.hProcess), "assign tree job");
        if (inherited) {
            fprintf(stderr, "[launcher] pid=%lu prepared-by=inherited-relay\n", child.dwProcessId);
        } else if (!state->modules()) {
            fprintf(stderr, "[launcher] pid=%lu classification=skipped hooks=0 debugger=none\n",
                    child.dwProcessId);
        } else {
            ProcessImage image{};
            check_nt(identify_process(state->api, child.hProcess, image,
                                      state->enabled(Module::exe_placement)),
                     "classify actual root image");
            if (reserved && !image.related)
                check_nt(status_invalid_image, "verify preflight MSYS root");
            if (image.related && (state->modules() & acl_modules)) {
                // A cold MSYS start needs a real primary-token handle. A token
                // inherited through an MSYS-created native bridge may deny this,
                // even though our own read-only pseudo-token queries succeeded.
                HANDLE root_token = nullptr;
                check(OpenProcessToken(child.hProcess, TOKEN_QUERY, &root_token),
                      "query MSYS root token before initialization");
                CloseHandle(root_token);
            }
            if (image.related || native_relay) {
                object_directory.reset(configure_security(*state, session_tag));
                if (native_relay)
                    check_nt(check_child_context(state->api, child.hProcess, *state),
                             "root relay security context");
                if (image.related)
                    check_nt(prepare_process(state->api, child.hProcess, child.hThread, image,
                                             *state),
                             "prepare MSYS root");
            }
            const auto modules = state->effective_modules(image.related);
            const auto installed = selected_hooks(modules);
            if (installed) {
                wchar_t own_path[32768];
                check(GetModuleFileNameW(nullptr, own_path, _countof(own_path)) != 0,
                      "locate agent");
                inject_root(child.hProcess, installed, *state,
                            fs::path(own_path).parent_path() / L"msys-sandbox-compat.dll");
            }
            if (reserved)
                check_nt(release_heap_reservation(state->api, child.hProcess, *state),
                         "release MSYS heap window");
            fprintf(
                stderr,
                "[launcher] pid=%lu classification=live-imports root=%s hooks=%zu debugger=none\n",
                child.dwProcessId, image.related ? "msys" : "native",
                std::bitset<hook_count>(installed).count());
            if (trace) {
                fprintf(stderr, "[launcher] modules=%02lx", static_cast<ULONG>(modules));
                for (const auto &option : module_options)
                    if (modules & bit(option.module))
                        fprintf(stderr, " %ls", option.name);
                fputc('\n', stderr);
            }
        }
        check(::ResumeThread(child.hThread) != static_cast<DWORD>(-1), "resume root");
        CloseHandle(child.hThread);
        child.hThread = nullptr;
        DWORD message = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED overlapped = nullptr;
        do {
            check(GetQueuedCompletionStatus(completion.get(), &message, &key, &overlapped, INFINITE),
                  "wait process tree");
            if (key == Pseudoconsole::output_failure_key)
                check_conpty_output();
        } while (key != reinterpret_cast<ULONG_PTR>(job.get()) ||
                 message != JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO);
        DWORD result = 1;
        check(GetExitCodeProcess(child.hProcess, &result), "root exit code");
        pty.close();
        check_conpty_output();
        fprintf(stderr, "[summary] exit=%lu\n", result);
        CloseHandle(child.hProcess);
        return static_cast<int>(result);
    } catch (...) {
        ::TerminateProcess(child.hProcess, 1);
        job.reset();
        if (child.hThread)
            CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        throw;
    }
} catch (const std::exception &error) {
    fprintf(stderr, "[fatal] %s\n", error.what());
    return 1;
}
