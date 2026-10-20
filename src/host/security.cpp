#include "host.h"
#include <sddl.h>
#include <securityappcontainer.h>

namespace msys_compat {
HANDLE configure_security(AgentState &state) {
    // MSYS-created native descendants can deny reopening their primary token.
    // The current-token pseudo handle provides the read-only queries we need.
    HANDLE token = GetCurrentProcessToken();
    BYTE user[4096], package[4096];
    DWORD size = 0;
    check(GetTokenInformation(token, TokenUser, user, sizeof(user), &size), "TokenUser");
    check(GetTokenInformation(token, TokenAppContainerSid, package, sizeof(package), &size),
          "TokenAppContainerSid");
    DWORD default_bytes = 0;
    GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &default_bytes);
    std::vector<BYTE> default_info(default_bytes);
    check(default_bytes && GetTokenInformation(token, TokenDefaultDacl, default_info.data(),
                                               default_bytes, &default_bytes),
          "TokenDefaultDacl");
    auto acl = reinterpret_cast<TOKEN_DEFAULT_DACL *>(default_info.data())->DefaultDacl;
    if (acl) {
        check(IsValidAcl(acl) && acl->AclSize <= sizeof(state.token_default_dacl),
              "sandbox default DACL capacity");
        memcpy(state.token_default_dacl, acl, acl->AclSize);
        state.token_default_dacl_bytes = acl->AclSize;
    }
    auto sid = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer;
    check(sid != nullptr || IsTokenRestricted(token), "restricted execution context required");
    if (sid) {
        LPWSTR user_text = nullptr, package_text = nullptr;
        check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(user)->User.Sid, &user_text),
              "user SID");
        check(ConvertSidToStringSidW(sid, &package_text), "package SID");
        auto sddl = L"D:P(A;;GA;;;" + std::wstring(user_text) + L")(A;;GA;;;SY)(A;;GA;;;" +
                    package_text + L")";
        LocalFree(user_text);
        LocalFree(package_text);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        ULONG bytes = 0;
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                   &descriptor, &bytes),
              "private object descriptor");
        check(bytes <= sizeof(state.descriptor), "descriptor capacity");
        memcpy(state.descriptor, descriptor, bytes);
        LocalFree(descriptor);
    } else {
        SECURITY_DESCRIPTOR descriptor{};
        check(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION),
              "restricted object descriptor");
        check(SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE), "restricted object ACL");
        DWORD bytes = sizeof(state.descriptor);
        check(MakeSelfRelativeSD(&descriptor, state.descriptor, &bytes),
              "restricted descriptor capacity");
    }

    // AppContainer namespaces are supplied by Windows. Restricted tokens need
    // a per-launch directory so unrelated MSYS sessions cannot precreate it
    // with a different ACL. Native intermediaries inherit the launch tag.
    wchar_t relative[object_root_chars]{};
    ULONG chars = 0;
    if (sid)
        check(GetAppContainerNamedObjectPath(token, nullptr, _countof(relative), relative, &chars),
              "AppContainer object namespace");
    else
        wcscpy_s(relative, L"BaseNamedObjects");
    DWORD session = 0;
    check(GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size),
          "TokenSessionId");
    auto root = L"\\Sessions\\" + std::to_wstring(session) + L"\\" + relative;
    HANDLE directory = nullptr;
    if (!sid) {
        wchar_t tag[32]{};
        auto count = GetEnvironmentVariableW(L"MSYS_COMPAT_SESSION", tag, _countof(tag));
        check(count < _countof(tag), "inherited compatibility session");
        for (DWORD i = 0; i < count; ++i)
            check(tag[i] >= L'0' && tag[i] <= L'9', "compatibility session tag");
        auto identity = count ? std::wstring(tag) : std::to_wstring(GetCurrentProcessId());
        check(SetEnvironmentVariableW(L"MSYS_COMPAT_SESSION", identity.c_str()),
              "inherit compatibility session");
        root += L"\\msys-compat-" + identity;
        check(root.size() < object_root_chars, "namespace capacity");
        UNICODE_STRING name{static_cast<USHORT>(root.size() * sizeof(wchar_t)),
                            static_cast<USHORT>((root.size() + 1) * sizeof(wchar_t)), root.data()};
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, nullptr,
                                   state.descriptor);
        check_nt(
            state.api.create_directory(&directory, STANDARD_RIGHTS_REQUIRED | 0xf, &attributes),
            "restricted compatibility namespace");
    }
    check(root.size() < object_root_chars, "namespace capacity");
    memcpy(state.object_root, root.c_str(), (root.size() + 1) * 2);
    state.root_chars = static_cast<uint32_t>(root.size());
    return directory;
}
} // namespace msys_compat
