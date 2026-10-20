#include "msys_compat/command_line.h"
using msys_compat::quote;
// Minimal native PSEC 1.0 launcher. No AppContainer/DACL fallback.
#include "ProcessSecurityEnvironment_generated.h"
#include <nlohmann/json.hpp>
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
    if (argc < 3) {
        fprintf(stderr, "Usage: psec-run policy.json program.exe [args...]\n");
        return 2;
    }
    std::ifstream stream{std::filesystem::path(argv[1])};
    if (!stream)
        throw std::runtime_error("open policy");
    auto config = nlohmann::json::parse(stream);
    auto fs = config.at("filesystem");
    auto paths = [&](const char *key) {
        auto values = fs.value(key, std::vector<std::string>{});
        for (auto &p : values)
            if (p.find('\0') != std::string::npos || !std::filesystem::u8path(p).is_absolute())
                throw std::runtime_error("absolute policy paths required");
        return values;
    };
    auto rw = paths("readwritePaths"), ro = paths("readonlyPaths"), deny = paths("deniedPaths");
    flatbuffers::FlatBufferBuilder buffer;
    auto rwv = buffer.CreateVectorOfStrings(rw), rov = buffer.CreateVectorOfStrings(ro),
         dv = buffer.CreateVectorOfStrings(deny);
    namespace P = ProcessSecurityEnvironmentLayout;
    P::SchemaVersion version(1, 0);
    auto root = P::CreateProcessSecurityEnvironment(buffer, &version, 0, false, 0, rwv, rov, dv);
    P::FinishProcessSecurityEnvironmentBuffer(buffer, root);
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
    UINT64 flags = 0;
    hrcheck(support(&flags), "query PSEC support");
    if (!deny.empty() && !(flags & 1))
        throw std::runtime_error("PSEC fs_deny unavailable");
    hrcheck(create(buffer.GetBufferPointer(), (DWORD)buffer.GetSize(), 0, &r.environment),
            "CreateProcessSecurityEnvironment");
    fprintf(stderr, "[PSEC] native contract=1.0 support=%llx; no fallback\n", flags);
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
    auto executable = std::filesystem::absolute(argv[2]).wstring();
    auto command = quote(executable);
    for (int i = 3; i < argc; ++i)
        command += L" " + quote(argv[i]);
    r.job = CreateJobObjectW(nullptr, nullptr);
    check(r.job != nullptr, "CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(
        SetInformationJobObject(r.job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "kill-on-close job");
    check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr,
                         &startup.StartupInfo, &r.child),
          "CreateProcess PSEC");
    if (!AssignProcessToJobObject(r.job, r.child.hProcess)) {
        TerminateProcess(r.child.hProcess, 1);
        check(FALSE, "AssignProcessToJobObject");
    }
    check(ResumeThread(r.child.hThread) != (DWORD)-1, "ResumeThread");
    check(WaitForSingleObject(r.child.hProcess, INFINITE) == WAIT_OBJECT_0, "wait workload");
    DWORD exit = 1;
    check(GetExitCodeProcess(r.child.hProcess, &exit), "workload exit code");
    return (int)exit;
} catch (const std::exception &ex) {
    fprintf(stderr, "[PSEC error] %s\n", ex.what());
    return 1;
}
