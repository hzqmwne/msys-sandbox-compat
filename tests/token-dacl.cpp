#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>
#include <vector>

// Run in a disposable PSEC, without descendants. Restore the token even though
// this is an experiment: TokenDefaultDacl is deliberately not our runtime fix.
int wmain() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &token))
        return 2;
    BYTE user[4096], package[4096];
    DWORD size = 0;
    if (!GetTokenInformation(token, TokenUser, user, sizeof(user), &size) ||
        !GetTokenInformation(token, TokenAppContainerSid, package, sizeof(package), &size))
        return 3;
    GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &size);
    std::vector<BYTE> old(size);
    if (!GetTokenInformation(token, TokenDefaultDacl, old.data(), size, &size))
        return 4;
    LPWSTR user_sid = nullptr, package_sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(user)->User.Sid, &user_sid) ||
        !ConvertSidToStringSidW(
            reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer,
            &package_sid))
        return 5;
    auto explicit_sddl = L"D:P(A;;GA;;;" + std::wstring(user_sid) + L")";
    auto default_sddl = explicit_sddl + L"(A;;GA;;;" + package_sid + L")";
    PSECURITY_DESCRIPTOR explicit_sd = nullptr, default_sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(explicit_sddl.c_str(), 1,
                                                              &explicit_sd, nullptr) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(default_sddl.c_str(), 1, &default_sd,
                                                              nullptr))
        return 6;
    PACL acl = nullptr;
    BOOL present = FALSE, inherited = FALSE;
    GetSecurityDescriptorDacl(default_sd, &present, &acl, &inherited);
    TOKEN_DEFAULT_DACL replacement{acl};
    auto test = [&](const wchar_t *label, bool explicit_descriptor) {
        auto name = L"msys-compat-dacl-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + label;
        SECURITY_ATTRIBUTES security{sizeof(security), explicit_sd, FALSE};
        HANDLE created =
            CreateMutexW(explicit_descriptor ? &security : nullptr, FALSE, name.c_str());
        if (!created) {
            fwprintf(stderr, L"%ls create=%lu\n", label, GetLastError());
            return false;
        }
        HANDLE reopened = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, name.c_str());
        auto error = reopened ? 0 : GetLastError();
        fwprintf(stdout, L"%ls reopen=%ls error=%lu\n", label, reopened ? L"allowed" : L"denied",
                 error);
        if (reopened)
            CloseHandle(reopened);
        CloseHandle(created);
        return reopened != nullptr;
    };
    bool before = test(L"original-default", false);
    if (!SetTokenInformation(token, TokenDefaultDacl, &replacement, sizeof(replacement)))
        return 7;
    bool default_allowed = test(L"supplemented-default", false);
    bool explicit_allowed = test(L"explicit-user-only-descriptor", true);
    BOOL restored =
        SetTokenInformation(token, TokenDefaultDacl, old.data(), static_cast<DWORD>(old.size()));
    printf("default-before=%d default-after=%d explicit-after=%d restored=%d\n", before,
           default_allowed, explicit_allowed, restored);
    LocalFree(user_sid);
    LocalFree(package_sid);
    LocalFree(explicit_sd);
    LocalFree(default_sd);
    CloseHandle(token);
    return default_allowed && !explicit_allowed && restored ? 0 : 1;
}
