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
struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

#ifdef MSYS_SANDBOX_COMPAT_EMBEDDED
constexpr bool allow_legacy_cli = false;
#else
constexpr bool allow_legacy_cli = true;
#endif

constexpr char usage[] =
    "Usage: msys-sandbox-compat-shim [OPTIONS] -- COMMAND [ARGUMENTS...]\n"
    "       msys-sandbox-compat-shim --help | --version\n";

constexpr char options_help[] =
    "\n"
    "  --terminal=auto|inherit|conpty  Select terminal behavior (default: auto).\n"
    "      auto                       Bridge only console streams when available.\n"
    "      inherit                    Pass standard handles directly to COMMAND.\n"
    "      conpty                     Start an inner ConPTY with VT input on stdin.\n"
    "  --conpty-size=COLSxROWS         Use a fixed inner ConPTY size.\n"
    "  --native-relay=on|off          Relay through native processes (default: on).\n"
    "  --disable-modules=NAME[,NAME...]  Disable compatibility modules.\n";

constexpr struct {
    const wchar_t *name;
    Module module;
    const char *description;
} module_options[] = {
    {L"propagation", Module::propagation, "Prepare child processes."},
    {L"heap-window", Module::heap_window, "Reserve the MSYS address window during creation."},
    {L"exe-placement", Module::exe_placement, "Keep MSYS executable mappings compatible with fork."},
    {L"dll-placement", Module::dll_placement, "Prefer compatible MSYS DLL image addresses."},
    {L"ipc", Module::ipc, "Adapt the MSYS named-object namespace and access."},
    {L"process-dacl", Module::process_dacl, "Adapt process and thread object access."},
    {L"token-dacl", Module::token_dacl, "Adapt the default object DACL."},
};

uint32_t module_option(std::wstring_view name) {
    for (const auto &option : module_options)
        if (name == option.name)
            return bit(option.module);
    return 0;
}

uint32_t module_list(std::wstring_view list) {
    uint32_t modules = 0;
    for (;;) {
        const auto comma = list.find(L',');
        const auto name = list.substr(0, comma);
        const auto module = module_option(name);
        if (!module)
            throw UsageError(name.empty() ? "empty name in --disable-modules"
                                          : "unknown compatibility module: " + fs::path(name).u8string());
        modules |= module;
        if (comma == std::wstring_view::npos)
            return modules;
        list.remove_prefix(comma + 1);
    }
}
} // namespace

static BOOL WINAPI wait_control(DWORD event) { return event == CTRL_C_EVENT; }

int wmain(int argc, wchar_t **argv) try {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") {
        fputs(usage, stdout);
        fputs(options_help, stdout);
        fputs("\nModules:\n", stdout);
        for (const auto &option : module_options)
            fprintf(stdout, "  %-15ls %s\n", option.name, option.description);
        return 0;
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"--version") {
        puts(MSYS_SANDBOX_COMPAT_VERSION);
        return 0;
    }
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
    bool explicit_options = session_owner || !allow_legacy_cli;
    bool separated = false;
    int first = 1;
    if (session_owner) {
        if (argc < 7)
            throw UsageError("invalid console session arguments");
        disable_conpty = true;
        const HANDLE initial_error = stdio[2];
        session_stdio.receive(argv + 2, stdio);
        if (valid_handle(stdio[2]) && stdio[2] != initial_error)
            redirect_host_stderr(stdio[2]);
        first = 5;
    }
    while (first < argc) {
        const std::wstring_view option = argv[first];
        const auto equals = option.find(L'=');
        const auto key = option.substr(0, equals);
        const auto value = equals == std::wstring_view::npos ? std::wstring_view{}
                                                             : option.substr(equals + 1);
        if (option == L"--") {
            separated = true;
            ++first;
            break;
        } else if (key == L"--terminal" && equals != std::wstring_view::npos) {
            if (session_owner || (value != L"auto" && value != L"inherit" && value != L"conpty"))
                throw UsageError("invalid --terminal value");
            explicit_options = true;
            disable_conpty = value == L"inherit";
            force_conpty = value == L"conpty";
            ++first;
        } else if (key == L"--native-relay" && equals != std::wstring_view::npos) {
            if (value != L"on" && value != L"off")
                throw UsageError("--native-relay expects on or off");
            explicit_options = true;
            enable_native_relay |= value == L"on";
            disable_native_relay |= value == L"off";
            ++first;
        } else if (key == L"--disable-modules" && equals != std::wstring_view::npos) {
            explicit_options = true;
            disabled_modules |= module_list(value);
            ++first;
        } else if (key == L"--conpty-size" && equals != std::wstring_view::npos) {
            unsigned width = 0, height = 0;
            wchar_t extra = 0;
            if (session_owner ||
                swscanf_s(value.data(), L"%ux%u%c", &width, &height, &extra, 1) != 2 ||
                !width || width > 32767 || !height || height > 32767)
                throw UsageError("--conpty-size expects COLSxROWS");
            explicit_options = true;
            terminal_size = {static_cast<SHORT>(width), static_cast<SHORT>(height)};
            fixed_terminal_size = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--trace") {
            trace = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--native-relay") {
            enable_native_relay = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--no-native-relay") {
            disable_native_relay = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--disable-module") {
            if (first + 1 >= argc)
                throw std::runtime_error("--disable-module requires a module name");
            const auto module = module_option(argv[first + 1]);
            if (!module)
                throw std::runtime_error("unknown compatibility module");
            disabled_modules |= module;
            first += 2;
        } else if (allow_legacy_cli && option == L"--conpty") {
            force_conpty = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--no-conpty") {
            disable_conpty = true;
            ++first;
        } else if (allow_legacy_cli && option == L"--conpty-script" && first + 1 < argc) {
            force_conpty = true;
            input_script = argv[first + 1];
            first += 2;
        } else if (allow_legacy_cli && option == L"--conpty-size" && first + 1 < argc) {
            unsigned width = 0, height = 0;
            wchar_t extra = 0;
            check(swscanf_s(argv[first + 1], L"%ux%u%c", &width, &height, &extra, 1) == 2 &&
                      width > 0 && width <= 32767 && height > 0 && height <= 32767,
                  "terminal size WIDTHxHEIGHT");
            terminal_size = {static_cast<SHORT>(width), static_cast<SHORT>(height)};
            fixed_terminal_size = true;
            first += 2;
        } else if (allow_legacy_cli && option == L"--runtime" && first + 1 < argc) {
            // Retain the old spelling for existing launch commands.
            first += 2;
        } else {
            if (option.substr(0, 2) == L"--")
                throw UsageError("unknown option: " + fs::path(option).u8string());
            break;
        }
    }
    if (explicit_options && !separated)
        throw UsageError("expected -- before the command");
    if (first == argc || !*argv[first])
        throw UsageError("missing command");
    if (separated && disable_conpty && fixed_terminal_size)
        throw UsageError("--conpty-size requires auto or conpty terminal mode");
    if (separated && enable_native_relay && disable_native_relay)
        throw UsageError("conflicting --native-relay values");
    if (force_conpty && disable_conpty)
        throw std::runtime_error("--no-conpty conflicts with --conpty or --conpty-script");
    if (enable_native_relay && disable_native_relay)
        throw std::runtime_error("--no-native-relay conflicts with --native-relay");
    const bool propagation_disabled = (disabled_modules & bit(Module::propagation)) != 0;
    if (separated && enable_native_relay && propagation_disabled)
        throw UsageError("--native-relay=on requires the propagation module");
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
    const fs::path target(argv[first]);
    auto executable = target.has_parent_path() || !separated ? fs::absolute(target) : fs::path{};
    fs::path launcher_path;
    const auto own_path = [&]() -> const fs::path & {
        if (launcher_path.empty()) {
            std::wstring path(32768, L'\0');
            const auto length = GetModuleFileNameW(nullptr, path.data(),
                                                   static_cast<DWORD>(path.size()));
            check(length && length < path.size(), "locate launcher executable");
            path.resize(length);
            launcher_path = std::move(path);
        }
        return launcher_path;
    };
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
    std::wstring command;
    if (separated)
        command = command_tail(GetCommandLineW(), first);
    else {
        command = quote(executable.wstring());
        for (int index = first + 1; index < argc; ++index)
            command += L" " + quote(argv[index]);
    }
    if (conpty) {
        // Let a native session host own the console's automatically created
        // handles. It starts the target with explicit inherited stdio, so
        // MSYS may close its own copies without FreeConsole later closing
        // recycled handle values from KernelBase's console state.
        executable = own_path();
        auto session_command = quote(executable.wstring());
        session_command += session_stdio.prepare(
            stdio, auto_conpty ? console : ConsoleStreams{true, true, true});
        session_command += native_relay ? L" --native-relay=on" : L" --native-relay=off";
        std::wstring disabled_names;
        for (const auto &option : module_options)
            if (disabled_modules & bit(option.module)) {
                if (!disabled_names.empty())
                    disabled_names += L',';
                disabled_names += option.name;
            }
        if (!disabled_names.empty())
            session_command += L" --disable-modules=" + disabled_names;
        if (trace && allow_legacy_cli)
            session_command += L" --trace";
        command = session_command + L" -- " + command;
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
    check(create_root(executable.empty() ? nullptr : executable.c_str(), command.data(), startup, conpty,
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
            if ((related || native_relay) && state->enabled(Module::ipc))
                object_directory.reset(prepare_ipc_directory(*state));
            const auto modules = state->modules_for_image(related);
            const auto installed = selected_hooks(modules);
            if (installed || ((modules & bit(Module::exe_placement)) && !image.dynamic_base))
                inject_root(child.hProcess, installed, *state,
                            own_path().parent_path() / L"msys-sandbox-compat.dll");
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
        if (!session_owner)
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
} catch (const UsageError &error) {
    fprintf(stderr, "msys-sandbox-compat: %s\n", error.what());
    fputs(usage, stderr);
    return 2;
} catch (const std::exception &error) {
    fprintf(host_stderr(), "[fatal] %s\n", error.what());
    return 1;
}
