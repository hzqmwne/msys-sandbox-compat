#include "policy.h"
#include "msys_sandbox_compat/command_line.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
static void check(BOOL ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "%s: Win32 %lu\n", what, GetLastError());
        throw std::runtime_error(what);
    }
}
static void hrcheck(HRESULT hr, const char *what) {
    if (FAILED(hr)) {
        fprintf(stderr, "%s: HRESULT %08lx\n", what, (DWORD)hr);
        throw std::runtime_error(what);
    }
}
using CloseEnvironment = void(WINAPI *)(HANDLE);
using CheckVersion = HRESULT(WINAPI *)(DWORD, BOOLEAN *, DWORD *);
static constexpr char usage[] =
    "Run a command in a native Windows process security environment.\n\n"
    "Usage: psec-run --policy=FILE [--psec-version=auto|1.0|1.1] -- COMMAND [ARGUMENTS...]\n"
    "       psec-run -h | --help\n";
static BOOL WINAPI wait_control(DWORD event) { return event == CTRL_C_EVENT; }
struct Resources {
    HMODULE dll{};
    HANDLE environment{};
    CloseEnvironment close{};
    PROCESS_INFORMATION child{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes{};
    HANDLE job{};
    std::vector<HANDLE> stdio;
    ~Resources() {
        if (job)
            CloseHandle(job);
        if (child.hThread)
            CloseHandle(child.hThread);
        if (child.hProcess)
            CloseHandle(child.hProcess);
        if (attributes)
            DeleteProcThreadAttributeList(attributes);
        for (auto h : stdio)
            CloseHandle(h);
        if (environment)
            close(environment);
        if (dll)
            FreeLibrary(dll);
    }
};
int wmain(int argc, wchar_t **argv) try {
    const std::wstring_view request = argc == 2 ? argv[1] : L"";
    if (request == L"-h" || request == L"--help") {
        fputs(usage, stdout);
        return 0;
    }
    std::filesystem::path policy_file;
    int first = 1;
    int requested_minor = -1;
    for (; first < argc; ++first) {
        const std::wstring_view arg = argv[first];
        if (arg == L"--") {
            ++first;
            break;
        }
        if (arg.substr(0, 9) == L"--policy=")
            policy_file = arg.substr(9);
        else if (arg == L"--psec-version=auto")
            requested_minor = -1;
        else if (arg == L"--psec-version=1.0")
            requested_minor = 0;
        else if (arg == L"--psec-version=1.1")
            requested_minor = 1;
        else {
            fputs(usage, stderr);
            return 2;
        }
    }
    if (policy_file.empty() || first >= argc || !*argv[first]) {
        fputs(usage, stderr);
        return 2;
    }
    const psec_run::Policy policy(policy_file);
    const unsigned needed = policy.needs_minor_one() ? 1 : 0;
    const auto minor = requested_minor < 0 ? needed : static_cast<unsigned>(requested_minor);
    if (minor < needed)
        throw std::runtime_error("the requested policy needs PSEC 1.1");
    flatbuffers::FlatBufferBuilder buffer;
    policy.serialize(buffer, static_cast<uint16_t>(minor));
    std::vector<BYTE> attrs; // Must outlive Resources::attributes.
    Resources r;
    r.dll = LoadLibraryExW(L"processmodel.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    check(r.dll != nullptr, "load processmodel.dll");
    auto create = (HRESULT(WINAPI *)(LPCVOID, DWORD, DWORD, HANDLE *))GetProcAddress(
        r.dll, "CreateProcessSecurityEnvironment");
    auto support = (HRESULT(WINAPI *)(UINT64 *))GetProcAddress(
        r.dll, "QueryProcessSecurityEnvironmentSupport");
    r.close = (CloseEnvironment)GetProcAddress(r.dll, "CloseProcessSecurityEnvironment");
    if (!create || !support || !r.close)
        throw std::runtime_error("native PSEC exports required");
    const auto version_support = reinterpret_cast<CheckVersion>(
        GetProcAddress(r.dll, "IsProcessSecurityEnvironmentVersionSupported"));
    DWORD supported_minor = 0;
    BOOLEAN supported = TRUE;
    if (version_support)
        hrcheck(version_support(1, &supported, &supported_minor), "query PSEC version");
    if (!supported || supported_minor < minor)
        throw std::runtime_error("requested PSEC contract is unavailable");
    UINT64 flags = 0;
    hrcheck(support(&flags), "query PSEC support");
    if (!policy.deny.empty() && !(flags & psec_run::support_deny))
        throw std::runtime_error("PSEC fs_deny unavailable");
    if (!policy.enumerate.empty() && !(flags & psec_run::support_enumerate))
        throw std::runtime_error("PSEC fs_enumerate unavailable");
    if (policy.needs_ingress() && !(flags & psec_run::support_ingress))
        throw std::runtime_error("PSEC network ingress unavailable");
    hrcheck(create(buffer.GetBufferPointer(), (DWORD)buffer.GetSize(), 0, &r.environment),
            "CreateProcessSecurityEnvironment");
    fprintf(stderr, "[PSEC] native contract=1.%u support=%llx; no fallback\n", minor, flags);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    const DWORD ids[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    HANDLE *outputs[] = {&startup.StartupInfo.hStdInput, &startup.StartupInfo.hStdOutput,
                         &startup.StartupInfo.hStdError};
    for (int i = 0; i < 3; ++i) {
        HANDLE h = nullptr, source = GetStdHandle(ids[i]);
        if (source && source != INVALID_HANDLE_VALUE)
            check(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &h, 0, TRUE,
                                  DUPLICATE_SAME_ACCESS),
                  "duplicate stdio");
        else {
            SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
            h = CreateFileW(L"NUL", i ? GENERIC_WRITE : GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
            check(h != INVALID_HANDLE_VALUE, "NUL stdio");
        }
        r.stdio.push_back(h);
        *outputs[i] = h;
    }
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
    attrs.resize(size);
    r.attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)attrs.data();
    check(InitializeProcThreadAttributeList(r.attributes, 2, 0, &size), "init attributes");
    startup.lpAttributeList = r.attributes;
    check(UpdateProcThreadAttribute(r.attributes, 0, 35 | 0x00020000, &r.environment,
                                    sizeof(HANDLE), nullptr, nullptr),
          "PSEC process attribute");
    check(UpdateProcThreadAttribute(r.attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    r.stdio.data(), r.stdio.size() * sizeof(HANDLE), nullptr,
                                    nullptr),
          "stdio handle list");
    const std::filesystem::path target(argv[first]);
    const auto executable = target.has_parent_path()
                                ? std::filesystem::absolute(target)
                                : std::filesystem::path{};
    auto command = std::wstring(msys_sandbox_compat::command_tail(GetCommandLineW(), first));
    r.job = CreateJobObjectW(nullptr, nullptr);
    check(r.job != nullptr, "CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(
        SetInformationJobObject(r.job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "kill-on-close job");
    check(CreateProcessW(executable.empty() ? nullptr : executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr,
                         &startup.StartupInfo, &r.child),
          "CreateProcess PSEC");
    if (!AssignProcessToJobObject(r.job, r.child.hProcess)) {
        TerminateProcess(r.child.hProcess, 1);
        check(FALSE, "AssignProcessToJobObject");
    }
    check(SetConsoleCtrlHandler(wait_control, TRUE), "register PSEC waiting-host Ctrl+C handler");
    check(ResumeThread(r.child.hThread) != (DWORD)-1, "ResumeThread");
    check(WaitForSingleObject(r.child.hProcess, INFINITE) == WAIT_OBJECT_0, "wait workload");
    DWORD exit = 1;
    check(GetExitCodeProcess(r.child.hProcess, &exit), "workload exit code");
    return (int)exit;
} catch (const std::exception &ex) {
    fprintf(stderr, "[PSEC error] %s\n", ex.what());
    return 1;
}
