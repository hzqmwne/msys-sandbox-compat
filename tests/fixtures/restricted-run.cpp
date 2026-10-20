#include "msys_compat/command_line.h"
using msys_compat::quote;
// Test-only restricted-token runner. It changes ACLs only in a marked fixture directory.
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>
#include <utility>

static void check(BOOL ok, const char *operation) {
    if (!ok) {
        fprintf(stderr, "[restricted-error] %s: Win32 %lu\n", operation, GetLastError());
        throw std::runtime_error(operation);
    }
}

static std::wstring sid_string(PSID sid) {
    LPWSTR text = nullptr;
    check(ConvertSidToStringSidW(sid, &text), "SID text");
    std::wstring result(text);
    LocalFree(text);
    return result;
}

static std::vector<BYTE> token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD bytes = 0;
    GetTokenInformation(token, kind, nullptr, 0, &bytes);
    std::vector<BYTE> result(bytes);
    check(bytes && GetTokenInformation(token, kind, result.data(), bytes, &bytes), "token query");
    return result;
}

static PSECURITY_DESCRIPTOR security(const std::wstring &sddl) {
    PSECURITY_DESCRIPTOR result = nullptr;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), 1, &result, nullptr),
          "fixture descriptor");
    return result;
}

static void file_security(const std::filesystem::path &path, const std::wstring &sddl) {
    auto sd = security(sddl);
    check(SetFileSecurityW(path.c_str(),
                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd),
          "fixture file ACL");
    LocalFree(sd);
}

static void fixture_file(const std::filesystem::path &path, const std::wstring &sddl) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    check(file != INVALID_HANDLE_VALUE, "create fixture");
    DWORD written = 0;
    check(WriteFile(file, "fixture-original\n", 17, &written, nullptr), "write fixture");
    CloseHandle(file);
    file_security(path, sddl);
}

static int probe(const std::filesystem::path &workspace) {
    HANDLE token = GetCurrentProcessToken();
    auto package = token_info(token, TokenAppContainerSid);
    auto restricting = token_info(token, TokenRestrictedSids);
    auto count = reinterpret_cast<TOKEN_GROUPS *>(restricting.data())->GroupCount;
    check(
        IsTokenRestricted(token) && count == 4 &&
            !reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package.data())->TokenAppContainer,
        "workload retained restricted token");
    for (auto operation : {std::pair{L"readonly.txt", DWORD(GENERIC_WRITE)},
                           std::pair{L"readonly.txt", DWORD(WRITE_DAC)},
                           std::pair{L"denied.txt", DWORD(GENERIC_READ)}}) {
        HANDLE file = CreateFileW((workspace / operation.first).c_str(), operation.second,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD error = GetLastError();
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        check(file == INVALID_HANDLE_VALUE && error == ERROR_ACCESS_DENIED,
              "restricted file boundary");
    }
    puts("RESTRICTED-TOKEN-AND-ACL-PASS");
    return 0;
}

int wmain(int argc, wchar_t **argv) try {
    if (argc == 3 && std::wstring(argv[1]) == L"probe")
        return probe(argv[2]);
    if (argc < 4 || (std::wstring(argv[1]) != L"write" && std::wstring(argv[1]) != L"full"))
        return 2;
    bool write_only = std::wstring(argv[1]) == L"write";
    auto workspace = std::filesystem::absolute(argv[2]);
    check(std::filesystem::is_directory(workspace) &&
              std::filesystem::exists(workspace / L".restricted-fixture") &&
              !(GetFileAttributesW(workspace.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT),
          "marked test workspace required");
    HANDLE original = nullptr;
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &original), "open runner token");
    auto user = token_info(original, TokenUser);
    auto groups = token_info(original, TokenGroups);
    auto list = reinterpret_cast<TOKEN_GROUPS *>(groups.data());
    PSID logon = nullptr;
    for (DWORD i = 0; i < list->GroupCount; ++i)
        if ((list->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            logon = list->Groups[i].Sid;
    check(logon != nullptr, "logon SID");
    std::vector<BYTE> world(SECURITY_MAX_SID_SIZE), users(SECURITY_MAX_SID_SIZE),
        authenticated(SECURITY_MAX_SID_SIZE), administrators(SECURITY_MAX_SID_SIZE);
    for (auto entry : {std::pair{WinWorldSid, &world}, std::pair{WinBuiltinUsersSid, &users},
                       std::pair{WinAuthenticatedUserSid, &authenticated},
                       std::pair{WinBuiltinAdministratorsSid, &administrators}}) {
        DWORD size = static_cast<DWORD>(entry.second->size());
        check(CreateWellKnownSid(entry.first, nullptr, entry.second->data(), &size),
              "well-known SID");
    }
    auto user_sid = sid_string(reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid);
    auto logon_sid = sid_string(logon);
    auto object_sddl = L"D:P(A;;GA;;;" + logon_sid + L")(A;;GA;;;SY)(A;;RC;;;OW)";
    auto sd = security(object_sddl);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), sd, TRUE};
    auto directory_sddl = L"D:P(A;OICI;FA;;;" + user_sid + L")(A;OICI;FA;;;" + logon_sid +
                          L")(A;OICI;FA;;;SY)(A;;RC;;;OW)";
    file_security(workspace, directory_sddl);
    std::filesystem::create_directories(workspace / L"tmp");
    std::filesystem::create_directories(workspace / L"home");
    auto readonly = workspace / L"readonly";
    check(std::filesystem::is_directory(readonly) &&
              !(GetFileAttributesW(readonly.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT),
          "staged test runtime required");
    auto readonly_sddl =
        L"D:P(A;;FA;;;" + user_sid + L")(A;;FRFX;;;" + logon_sid + L")(A;;FA;;;SY)(A;;RC;;;OW)";
    file_security(readonly, readonly_sddl);
    for (const auto &file : std::filesystem::directory_iterator(readonly)) {
        check(file.is_regular_file() &&
                  !(GetFileAttributesW(file.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT),
              "regular staged fixture required");
        file_security(file.path(), readonly_sddl);
    }
    for (auto name : {L"readonly.txt", L"denied.txt"})
        if (std::filesystem::exists(workspace / name))
            file_security(workspace / name, L"D:P(A;;FA;;;" + user_sid + L")(A;;FA;;;SY)");
    fixture_file(workspace / L"readonly.txt",
                 L"D:P(A;;FA;;;" + user_sid + L")(A;;FR;;;" + logon_sid + L")(A;;RC;;;OW)");
    fixture_file(workspace / L"denied.txt", L"D:P(D;;FRFW;;;" + user_sid + L")(A;;RCWD;;;" +
                                                user_sid + L")(A;;FA;;;SY)(A;;RC;;;OW)");
    SID_AND_ATTRIBUTES restricting[] = {
        {logon, 0}, {world.data(), 0}, {users.data(), 0}, {authenticated.data(), 0}};
    SID_AND_ATTRIBUTES disable{administrators.data(), 0};
    HANDLE restricted = nullptr;
    DWORD flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | (write_only ? WRITE_RESTRICTED : 0);
    check(CreateRestrictedToken(original, flags, 1, &disable, 0, nullptr, _countof(restricting),
                                restricting, &restricted),
          "CreateRestrictedToken");
    PACL acl = nullptr;
    BOOL present = FALSE, inherited = FALSE;
    check(GetSecurityDescriptorDacl(sd, &present, &acl, &inherited), "default ACL");
    TOKEN_DEFAULT_DACL default_dacl{acl};
    check(SetTokenInformation(restricted, TokenDefaultDacl, &default_dacl, sizeof(default_dacl)),
          "sandbox default ACL");
    check(SetKernelObjectSecurity(restricted, DACL_SECURITY_INFORMATION, sd), "sandbox token ACL");
    auto package = token_info(restricted, TokenAppContainerSid);
    check(!reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package.data())->TokenAppContainer &&
              IsTokenRestricted(restricted),
          "restricted non-AppContainer token");
    fprintf(stderr, "[restricted] mode=%ls flags=%lx restricting=4 appcontainer=0 default=%ls\n",
            argv[1], flags, object_sddl.c_str());
    std::wstring command = quote(argv[3]);
    for (int i = 4; i < argc; ++i)
        command += L" " + quote(argv[i]);
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child{};
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    check(job != nullptr, "fixture job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "fixture job limits");
    check(CreateProcessAsUserW(restricted, argv[3], command.data(), &attributes, &attributes, TRUE,
                               CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, workspace.c_str(),
                               &startup, &child),
          "create restricted workload");
    if (!AssignProcessToJobObject(job, child.hProcess)) {
        TerminateProcess(child.hProcess, 3);
        check(FALSE, "assign fixture job");
    }
    check(ResumeThread(child.hThread) != DWORD(-1), "resume fixture workload");
    DWORD waited = WaitForSingleObject(child.hProcess, 90000);
    if (waited != WAIT_OBJECT_0)
        TerminateJobObject(job, 4);
    DWORD result = 4;
    GetExitCodeProcess(child.hProcess, &result);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    CloseHandle(job);
    CloseHandle(restricted);
    CloseHandle(original);
    LocalFree(sd);
    return static_cast<int>(result);
} catch (...) {
    return 1;
}
