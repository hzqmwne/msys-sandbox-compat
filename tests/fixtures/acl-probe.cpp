// Loaded into real MSYS Perl: default settings must use the current input ACL.
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
static void report(const std::string &text) {
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text.data(), static_cast<DWORD>(text.size()),
              &written, nullptr);
}
static std::vector<BYTE> defaults() {
    DWORD bytes = 0;
    GetTokenInformation(GetCurrentProcessToken(), TokenDefaultDacl, nullptr, 0, &bytes);
    std::vector<BYTE> result(bytes);
    if (!bytes || !GetTokenInformation(GetCurrentProcessToken(), TokenDefaultDacl, result.data(),
                                       bytes, &bytes))
        ExitProcess(90);
    return result;
}
static bool equal_acl(PACL a, PACL b) {
    return (!a || !b) ? a == b : a->AclSize == b->AclSize && !memcmp(a, b, a->AclSize);
}
static bool object_contract(PSID user, PSID compatibility, PSID group) {
    using CreateDirectory = LONG(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using CreateMutant = LONG(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
    auto module = GetModuleHandleW(L"ntdll.dll");
    auto directory =
        reinterpret_cast<CreateDirectory>(GetProcAddress(module, "NtCreateDirectoryObject"));
    auto mutant = reinterpret_cast<CreateMutant>(GetProcAddress(module, "NtCreateMutant"));
    LPWSTR user_text = nullptr, group_text = nullptr;
    ConvertSidToStringSidW(user, &user_text);
    ConvertSidToStringSidW(group, &group_text);
    auto sddl = L"O:" + std::wstring(user_text) + L"G:" + group_text + L"D:P(A;;GA;;;" + user_text +
                L")(A;;GA;;;SY)";
    LocalFree(user_text);
    LocalFree(group_text);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), 1, &sd, nullptr))
        return false;
    auto path = L"\\BaseNamedObjects\\msys-acl-contract-" + std::to_wstring(GetCurrentProcessId());
    UNICODE_STRING name{static_cast<USHORT>(path.size() * 2),
                        static_cast<USHORT>((path.size() + 1) * 2), path.data()};
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, sd);
    HANDLE parent = nullptr, child = nullptr;
    auto status = directory(&parent, STANDARD_RIGHTS_REQUIRED | 0xf, &attributes);
    bool pass = status >= 0;
    if (pass) {
        wchar_t leaf[] = L"contract";
        UNICODE_STRING relative{16, 18, leaf};
        InitializeObjectAttributes(&attributes, &relative, OBJ_CASE_INSENSITIVE, parent, sd);
        status = mutant(&child, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 1, &attributes, FALSE);
        pass = status >= 0;
    }
    if (pass) {
        DWORD bytes = 0;
        GetKernelObjectSecurity(child,
                                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION,
                                nullptr, 0, &bytes);
        std::vector<BYTE> actual(bytes);
        pass = bytes &&
               GetKernelObjectSecurity(child,
                                       OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                           DACL_SECURITY_INFORMATION,
                                       actual.data(), bytes, &bytes);
        if (pass) {
            PSID owner = nullptr, actual_group = nullptr;
            BOOL defaulted = FALSE, present = FALSE;
            GetSecurityDescriptorOwner(actual.data(), &owner, &defaulted);
            GetSecurityDescriptorGroup(actual.data(), &actual_group, &defaulted);
            PACL acl = nullptr;
            GetSecurityDescriptorDacl(actual.data(), &present, &acl, &defaulted);
            DWORD user_mask = 0, compat_mask = 0;
            if (acl)
                for (WORD i = 0; i < acl->AceCount; ++i) {
                    void *entry = nullptr;
                    GetAce(acl, i, &entry);
                    auto ace = static_cast<ACCESS_ALLOWED_ACE *>(entry);
                    if (EqualSid(&ace->SidStart, user))
                        user_mask |= ace->Mask;
                    if (EqualSid(&ace->SidStart, compatibility))
                        compat_mask |= ace->Mask;
                }
            SECURITY_DESCRIPTOR_CONTROL control = 0;
            DWORD revision = 0;
            GetSecurityDescriptorControl(actual.data(), &control, &revision);
            pass = owner && actual_group && EqualSid(owner, user) &&
                   EqualSid(actual_group, group) && acl && acl->AceCount == 3 && user_mask &&
                   user_mask == compat_mask && (control & SE_DACL_PROTECTED);
        }
    }
    if (child)
        CloseHandle(child);
    if (parent)
        CloseHandle(parent);
    LocalFree(sd);
    return pass;
}
extern "C" __declspec(dllexport) void dacl_probe(void *, void *) {
    auto snapshot = defaults();
    HANDLE primary = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_DUPLICATE,
                          &primary))
        ExitProcess(91);
    BYTE user_bytes[1024]{}, package_bytes[1024]{};
    DWORD returned = 0;
    if (!GetTokenInformation(primary, TokenUser, user_bytes, sizeof(user_bytes), &returned) ||
        !GetTokenInformation(primary, TokenAppContainerSid, package_bytes, sizeof(package_bytes),
                             &returned))
        ExitProcess(92);
    auto package =
        reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package_bytes)->TokenAppContainer;
    BYTE groups_bytes[8192]{};
    if (!package &&
        GetTokenInformation(primary, TokenGroups, groups_bytes, sizeof(groups_bytes), &returned)) {
        auto groups = reinterpret_cast<TOKEN_GROUPS *>(groups_bytes);
        for (DWORD i = 0; i < groups->GroupCount; ++i)
            if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                package = groups->Groups[i].Sid;
    }
    LPWSTR sid_text = nullptr;
    ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(user_bytes)->User.Sid, &sid_text);
    std::wstring user(sid_text);
    LocalFree(sid_text);
    struct Case {
        const char *name;
        std::wstring sddl;
        DWORD mask;
    };
    std::vector<Case> cases{{"user-all", L"D:P(A;;GA;;;" + user + L")(A;;GA;;;SY)", GENERIC_ALL},
                            {"user-query", L"D:P(A;;0x8;;;" + user + L")(A;;GA;;;SY)", TOKEN_QUERY},
                            {"enabled-world", L"D:P(A;;0x8;;;WD)(A;;GA;;;SY)", TOKEN_QUERY},
                            {"system-only", L"D:P(A;;GA;;;SY)", 0},
                            {"user-deny", L"D:P(D;;0x8;;;" + user + L")(A;;GA;;;" + user + L")", 0},
                            {"world-deny", L"D:P(D;;0x8;;;WD)(A;;GA;;;" + user + L")", 0},
                            {"group-only", L"D:P(A;;GA;;;BA)", 0},
                            {"empty", L"D:P", 0},
                            {"inheriting-user", L"D:P(A;OICI;GA;;;" + user + L")", 0}};
    int failed = 0;
    BYTE primary_group[1024]{};
    bool object_ok =
        GetTokenInformation(primary, TokenPrimaryGroup, primary_group, sizeof(primary_group),
                            &returned) &&
        object_contract(reinterpret_cast<TOKEN_USER *>(user_bytes)->User.Sid, package,
                        reinterpret_cast<TOKEN_PRIMARY_GROUP *>(primary_group)->PrimaryGroup);
    report(std::string("MUTATION explicit-object pass=") + (object_ok ? "1" : "0") + "\n");
    if (!object_ok)
        ++failed;
    for (const auto &test : cases) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(test.sddl.c_str(), 1, &sd,
                                                                  nullptr))
            ExitProcess(93);
        PACL input = nullptr;
        BOOL present = FALSE, inherited = FALSE;
        GetSecurityDescriptorDacl(sd, &present, &input, &inherited);
        TOKEN_DEFAULT_DACL request{input};
        BOOL set = SetTokenInformation(primary, TokenDefaultDacl, &request, sizeof(request));
        auto actual = defaults();
        auto output = reinterpret_cast<TOKEN_DEFAULT_DACL *>(actual.data())->DefaultDacl;
        bool pass = set != FALSE;
        if (test.mask) {
            pass = pass && package && output && output->AceCount == input->AceCount + 1;
            for (WORD i = 0; pass && i < input->AceCount; ++i) {
                void *a = nullptr, *b = nullptr;
                GetAce(input, i, &a);
                GetAce(output, i, &b);
                pass = reinterpret_cast<ACE_HEADER *>(a)->AceSize ==
                           reinterpret_cast<ACE_HEADER *>(b)->AceSize &&
                       !memcmp(a, b, reinterpret_cast<ACE_HEADER *>(a)->AceSize);
            }
            void *last = nullptr;
            if (pass) {
                GetAce(output, output->AceCount - 1, &last);
                auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE *>(last);
                pass = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
                       ace->Mask == test.mask && EqualSid(&ace->SidStart, package);
            }
            if (pass) {
                TOKEN_DEFAULT_DACL repeat{output};
                pass = SetTokenInformation(primary, TokenDefaultDacl, &repeat, sizeof(repeat)) !=
                       FALSE;
                auto again = defaults();
                pass = pass &&
                       equal_acl(output,
                                 reinterpret_cast<TOKEN_DEFAULT_DACL *>(again.data())->DefaultDacl);
            }
        } else
            pass = pass && equal_acl(input, output);
        if (std::string(test.name) == "system-only") {
            wchar_t path[32768]{};
            GetModuleFileNameW(nullptr, path, _countof(path));
            const auto marker =
                L"acl-child-executed-" + std::to_wstring(GetCurrentProcessId()) + L".marker";
            DeleteFileW(marker.c_str());
            const auto line = L"\"" + std::wstring(path) + L"\" -e \"open(my $f,'>',q{" + marker +
                              L"}) or exit 91; print $f q{ran}; close $f; exit 73\"";
            auto command = line;
            STARTUPINFOW startup{sizeof(startup)};
            PROCESS_INFORMATION child{};
            BOOL created = CreateProcessW(path, command.data(), nullptr, nullptr, FALSE,
                                          CREATE_SUSPENDED, nullptr, nullptr, &startup, &child);
            DWORD error = created ? 0 : GetLastError();
            report("OBSERVATION system-only create=" + std::to_string(created) +
                   " error=" + std::to_string(error) + "\n");
            if (created) {
                HANDLE reopened = OpenProcess(PROCESS_DUP_HANDLE, FALSE, child.dwProcessId);
                const DWORD reopen_error = reopened ? ERROR_SUCCESS : GetLastError();
                report("OBSERVATION system-only reopen=" + std::to_string(reopen_error) + "\n");
                if (reopened)
                    CloseHandle(reopened);
                pass = pass && reopen_error == ERROR_ACCESS_DENIED;
                TerminateProcess(child.hProcess, 95);
                CloseHandle(child.hThread);
                CloseHandle(child.hProcess);
            }
            // A creation handle and a fresh open use different access checks.
            pass =
                pass && created && GetFileAttributesW(marker.c_str()) == INVALID_FILE_ATTRIBUTES;
            pass = SetTokenInformation(primary, TokenDefaultDacl, snapshot.data(),
                                       sizeof(TOKEN_DEFAULT_DACL)) &&
                   pass;
            command = line;
            child = {};
            BOOL control = CreateProcessW(path, command.data(), nullptr, nullptr, FALSE, 0, nullptr,
                                          nullptr, &startup, &child);
            bool control_ok = false;
            if (control) {
                DWORD code = 0;
                const auto waited = WaitForSingleObject(child.hProcess, 30000);
                control_ok = waited == WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess, &code) &&
                             code == 73 &&
                             GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES;
                if (waited != WAIT_OBJECT_0)
                    TerminateProcess(child.hProcess, 95);
                CloseHandle(child.hThread);
                CloseHandle(child.hProcess);
            }
            report("OBSERVATION restored-policy control=" + std::to_string(control_ok) + "\n");
            pass = pass && control_ok;
            DeleteFileW(marker.c_str());
        }
        report(std::string("MUTATION ") + test.name + " pass=" + (pass ? "1" : "0") + "\n");
        if (!pass)
            ++failed;
        SetTokenInformation(primary, TokenDefaultDacl, snapshot.data(), sizeof(TOKEN_DEFAULT_DACL));
        LocalFree(sd);
    }
    TOKEN_DEFAULT_DACL null_request{nullptr};
    bool null_ok = SetTokenInformation(primary, TokenDefaultDacl, &null_request,
                                       sizeof(null_request)) != FALSE;
    auto null_actual = defaults();
    auto null_acl = reinterpret_cast<TOKEN_DEFAULT_DACL *>(null_actual.data())->DefaultDacl;
    null_ok = null_ok && null_acl && null_acl->AceCount == 2;
    if (null_ok) {
        void *entry = nullptr;
        GetAce(null_acl, 0, &entry);
        auto world = static_cast<ACCESS_ALLOWED_ACE *>(entry);
        null_ok = world->Mask == GENERIC_ALL && IsWellKnownSid(&world->SidStart, WinWorldSid);
        GetAce(null_acl, 1, &entry);
        auto compat = static_cast<ACCESS_ALLOWED_ACE *>(entry);
        null_ok = null_ok && compat->Mask == GENERIC_ALL && EqualSid(&compat->SidStart, package);
    }
    report(std::string("MUTATION null pass=") + (null_ok ? "1" : "0") + "\n");
    if (!null_ok)
        ++failed;
    SetTokenInformation(primary, TokenDefaultDacl, snapshot.data(), sizeof(TOKEN_DEFAULT_DACL));
    ACL invalid{};
    invalid.AclRevision = 0;
    invalid.AclSize = sizeof(invalid);
    TOKEN_DEFAULT_DACL invalid_request{&invalid};
    bool invalid_ok =
        !SetTokenInformation(primary, TokenDefaultDacl, &invalid_request, sizeof(invalid_request));
    report(std::string("MUTATION invalid pass=") + (invalid_ok ? "1" : "0") + "\n");
    if (!invalid_ok)
        ++failed;
    auto final = defaults();
    bool restore_ok =
        equal_acl(reinterpret_cast<TOKEN_DEFAULT_DACL *>(snapshot.data())->DefaultDacl,
                  reinterpret_cast<TOKEN_DEFAULT_DACL *>(final.data())->DefaultDacl);
    report(std::string("MUTATION restored pass=") + (restore_ok ? "1" : "0") + "\n");
    if (!restore_ok)
        ++failed;
    HANDLE adjust_only = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &adjust_only)) {
        using Compare = LONG(NTAPI *)(HANDLE, HANDLE);
        auto compare = reinterpret_cast<Compare>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCompareObjects"));
        char line[128]{};
        auto status = compare ? compare(primary, adjust_only) : LONG(0xc00000bb);
        snprintf(line, sizeof(line), "OBSERVATION adjust-only NtCompareObjects=%08lx\n",
                 static_cast<ULONG>(status));
        report(line);
        PSECURITY_DESCRIPTOR requested = nullptr;
        auto sddl = L"D:P(A;;0x8;;;" + user + L")(A;;GA;;;SY)";
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), 1, &requested, nullptr);
        PACL acl = nullptr;
        BOOL present = FALSE, inherited = FALSE;
        GetSecurityDescriptorDacl(requested, &present, &acl, &inherited);
        TOKEN_DEFAULT_DACL value{acl};
        bool adjust_ok =
            SetTokenInformation(adjust_only, TokenDefaultDacl, &value, sizeof(value)) != FALSE;
        auto actual = defaults();
        auto output = reinterpret_cast<TOKEN_DEFAULT_DACL *>(actual.data())->DefaultDacl;
        void *last = nullptr;
        adjust_ok = adjust_ok && output && output->AceCount == acl->AceCount + 1 &&
                    GetAce(output, output->AceCount - 1, &last);
        if (adjust_ok) {
            auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE *>(last);
            adjust_ok = ace->Mask == TOKEN_QUERY && EqualSid(&ace->SidStart, package);
        }
        report(std::string("MUTATION adjust-only pass=") + (adjust_ok ? "1" : "0") + "\n");
        if (!adjust_ok)
            ++failed;
        SetTokenInformation(primary, TokenDefaultDacl, snapshot.data(), sizeof(TOKEN_DEFAULT_DACL));
        HANDLE other = nullptr;
        bool other_ok = DuplicateTokenEx(primary, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
                                         TokenPrimary, &other) != FALSE;
        if (other_ok) {
            other_ok = SetTokenInformation(other, TokenDefaultDacl, &value, sizeof(value)) != FALSE;
            DWORD size = 0;
            GetTokenInformation(other, TokenDefaultDacl, nullptr, 0, &size);
            std::vector<BYTE> other_bytes(size);
            other_ok =
                other_ok && size &&
                GetTokenInformation(other, TokenDefaultDacl, other_bytes.data(), size, &size);
            if (other_ok)
                other_ok = equal_acl(
                    acl, reinterpret_cast<TOKEN_DEFAULT_DACL *>(other_bytes.data())->DefaultDacl);
            CloseHandle(other);
        }
        report(std::string("MUTATION other-token pass=") + (other_ok ? "1" : "0") + "\n");
        if (!other_ok)
            ++failed;
        HANDLE query_only = nullptr;
        bool query_ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &query_only) != FALSE;
        if (query_ok) {
            query_ok = !SetTokenInformation(query_only, TokenDefaultDacl, &value, sizeof(value)) &&
                       GetLastError() == ERROR_ACCESS_DENIED;
            CloseHandle(query_only);
        }
        report(std::string("MUTATION query-only-denied pass=") + (query_ok ? "1" : "0") + "\n");
        if (!query_ok)
            ++failed;
        LocalFree(requested);
        CloseHandle(adjust_only);
    }
    CloseHandle(primary);
    report(std::string("MUTATION-SUITE ") + (failed ? "FAIL" : "PASS") + "\n");
    if (failed)
        ExitProcess(94);
}
