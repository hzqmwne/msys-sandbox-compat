#include "host.h"
#include "console_stdio.h"
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

int wmain(int argc, wchar_t **argv) try {
    bool trace = false;
    bool force_conpty = false;
    bool disable_conpty = false;
    bool fixed_terminal_size = false;
    bool enable_native_relay = false;
    bool disable_native_relay = false;
    uint32_t disabled_modules = 0;
    std::wstring input_script;
    COORD terminal_size{100, 30};
    StandardHandles stdio{GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE),
                          GetStdHandle(STD_ERROR_HANDLE)};
    SessionStdio session_stdio;
    const bool session_owner = argc > 1 && std::wstring_view(argv[1]) == session_stdio_option;
    int first = 1;
    if (session_owner) {
        if (argc < 7 || std::wstring_view(argv[5]) != L"--no-conpty")
            throw std::runtime_error("invalid console session arguments");
        const HANDLE initial_error = stdio[2];
        session_stdio.receive(argv + 2, stdio);
        if (valid_handle(stdio[2]) && stdio[2] != initial_error)
            redirect_host_stderr(stdio[2]);
        first = 5;
    }
    while (first < argc) {
        std::wstring option = argv[first];
        if (option == L"--trace") {
            trace = true;
            ++first;
        } else if (option == L"--native-relay") {
            enable_native_relay = true;
            ++first;
        } else if (option == L"--no-native-relay") {
            disable_native_relay = true;
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
        fprintf(host_stderr(), "Usage: msys-sandbox-compat [--trace] "
                        "[--native-relay | --no-native-relay] [--disable-module NAME] [--runtime DLL] PROGRAM "
                        "[arguments...]\n"
                        "Terminal options (before PROGRAM): "
                        "[--conpty | --no-conpty | --conpty-script FILE] "
                        "[--conpty-size WIDTHxHEIGHT]\n");
        return 2;
    }
    if (force_conpty && disable_conpty)
        throw std::runtime_error("--no-conpty conflicts with --conpty or --conpty-script");
    if (enable_native_relay && disable_native_relay)
        throw std::runtime_error("--no-native-relay conflicts with --native-relay");
    const bool propagation_disabled = (disabled_modules & bit(Module::propagation)) != 0;
    if (enable_native_relay && propagation_disabled)
        throw std::runtime_error("--native-relay requires the propagation module");
    bool native_relay = !disable_native_relay && !propagation_disabled;
    ConsoleStreams console{};
    ConsoleEndpoints endpoints;
    bool auto_conpty = false;
    if (!force_conpty && !disable_conpty) {
        std::transform(stdio.begin(), stdio.end(), console.begin(), console_handle);
        auto_conpty = endpoints.open(stdio, console);
    }
    const bool conpty = force_conpty || auto_conpty;
    check(SetConsoleCtrlHandler(wait_control, TRUE), "register waiting-host Ctrl+C handler");
    auto executable = fs::absolute(argv[first]);
    std::unique_ptr<AgentState> state;
    auto inherited = inherited_agent();
    std::unique_ptr<void, decltype(&CloseHandle)> object_directory(nullptr, CloseHandle);
    if (inherited) {
        if (disable_native_relay)
            throw std::runtime_error("--no-native-relay conflicts with inherited relay");
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
    std::unique_ptr<std::remove_pointer_t<LPPROC_THREAD_ATTRIBUTE_LIST>,
                    decltype(&DeleteProcThreadAttributeList)>
        attribute_list(nullptr, DeleteProcThreadAttributeList);
    if (conpty)
        pty.create(completion.get(), auto_conpty ? endpoints.input : stdio[0],
                   auto_conpty ? endpoints.output : stdio[1], input_script, terminal_size,
                   !fixed_terminal_size);
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
        auto session_command = quote(executable.wstring());
        if (auto_conpty)
            session_command += session_stdio.prepare(stdio, console);
        session_command += L" --no-conpty";
        session_command += native_relay ? L" --native-relay" : L" --no-native-relay";
        if (trace)
            session_command += L" --trace";
        for (const auto &option : module_options)
            if (disabled_modules & bit(option.module))
                session_command += std::wstring(L" --disable-module ") + option.name;
        command = session_command + L" " + command;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = conpty ? sizeof(startup) : sizeof(STARTUPINFOW);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    if (conpty) {
        // Explicit null std handles suppress Windows' legacy duplication of
        // the redirected parent's stdio. Console initialization then creates
        // handles for the requested pseudoconsole.
        const DWORD count = session_stdio.has_handles() ? 2 : 1;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &bytes);
        attribute_buffer.resize(bytes);
        startup.lpAttributeList =
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_buffer.data());
        check(InitializeProcThreadAttributeList(startup.lpAttributeList, count, 0, &bytes),
              "ConPTY attribute list");
        attribute_list.reset(startup.lpAttributeList);
        check(UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pty.handle,
                                        sizeof(HPCON), nullptr, nullptr),
              "ConPTY attribute");
        if (session_stdio.has_handles())
            session_stdio.set_inheritance_list(startup.lpAttributeList);
    } else {
        startup.StartupInfo.hStdInput = stdio[0];
        startup.StartupInfo.hStdOutput = stdio[1];
        startup.StartupInfo.hStdError = stdio[2];
    }
    PROCESS_INFORMATION child{};
    bool reserved = false;
    check(create_root(executable.c_str(), command.data(), startup, conpty,
                      !conpty || session_stdio.has_handles(), state.get(), child, reserved),
          "create suspended root");
    attribute_list.reset();
    session_stdio.close();
    if (conpty)
        pty.connected();
    try {
        check(AssignProcessToJobObject(job.get(), child.hProcess), "assign tree job");
        if (inherited) {
            fprintf(host_stderr(), "[launcher] pid=%lu prepared-by=inherited-relay\n",
                    child.dwProcessId);
        } else if (!state->modules()) {
            fprintf(host_stderr(), "[launcher] pid=%lu classification=skipped hooks=0 debugger=none\n",
                    child.dwProcessId);
        } else {
            bool related = false, wow64 = false;
            ImageRecord image{};
            const auto classification = identify_process(state->api, child.hProcess, related, &image);
            if (classification < 0) {
                query_wow64_process(state->api, child.hProcess, wow64);
                if (!wow64)
                    check_nt(classification, "classify actual root image");
            }
            if (reserved && !related)
                check_nt(status_invalid_image, "verify preflight MSYS root");
            if (related || native_relay)
                object_directory.reset(configure_security(*state));
            if (related && !state->plain_context && (state->modules() & acl_modules)) {
                // A cold MSYS start needs a real primary-token handle. A token
                // inherited through an MSYS-created native bridge may deny this,
                // even though our own read-only pseudo-token queries succeeded.
                HANDLE root_token = nullptr;
                check(OpenProcessToken(child.hProcess, TOKEN_QUERY, &root_token),
                      "query MSYS root token before initialization");
                CloseHandle(root_token);
            }
            if (native_relay)
                check_nt(check_child_context(state->api, child.hProcess, *state),
                         "root relay security context");
            if (related)
                check_nt(adapt_child_objects(child.hProcess, child.hThread, *state),
                         "adapt MSYS root objects");
            const auto modules = state->effective_modules(related);
            const auto installed = selected_hooks(modules);
            if (installed || ((modules & bit(Module::exe_placement)) && !image.dynamic_base)) {
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
                host_stderr(),
                "[launcher] pid=%lu classification=live-imports root=%s hooks=%zu debugger=none\n",
                child.dwProcessId, wow64 ? "wow64" : related ? "msys" : "native",
                std::bitset<hook_count>(installed).count());
            if (trace) {
                fprintf(host_stderr(), "[launcher] modules=%02lx", static_cast<ULONG>(modules));
                for (const auto &option : module_options)
                    if (modules & bit(option.module))
                        fprintf(host_stderr(), " %ls", option.name);
                fputc('\n', host_stderr());
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
        fprintf(host_stderr(), "[summary] exit=%lu\n", result);
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
    fprintf(host_stderr(), "[fatal] %s\n", error.what());
    return 1;
}
