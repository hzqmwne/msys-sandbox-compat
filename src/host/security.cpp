#include "host.h"
#include <securityappcontainer.h>

namespace msys_sandbox_compat {
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
    auto user_sid = reinterpret_cast<TOKEN_USER *>(user)->User.Sid;
    check(IsValidSid(user_sid) && GetLengthSid(user_sid) <= sizeof(state.user_sid),
          "user SID capacity");
    state.user_sid_bytes = GetLengthSid(user_sid);
    memcpy(state.user_sid, user_sid, state.user_sid_bytes);
    std::vector<BYTE> groups, restricting;
    if (!sid) {
        auto query = [&](TOKEN_INFORMATION_CLASS kind, std::vector<BYTE> &buffer) {
            DWORD bytes = 0;
            GetTokenInformation(token, kind, nullptr, 0, &bytes);
            buffer.resize(bytes);
            check(bytes && GetTokenInformation(token, kind, buffer.data(), bytes, &bytes),
                  "restricted object SID context");
        };
        query(TokenGroups, groups);
        query(TokenRestrictedSids, restricting);
        auto enabled = reinterpret_cast<TOKEN_GROUPS *>(groups.data());
        auto limits = reinterpret_cast<TOKEN_GROUPS *>(restricting.data());
        // The session logon identity is already both an enabled principal and
        // a restricting SID in the supported restricted-token environments.
        for (DWORD i = 0; i < enabled->GroupCount && !sid; ++i) {
            auto &group = enabled->Groups[i];
            if ((group.Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID ||
                !(group.Attributes & SE_GROUP_ENABLED) ||
                (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                continue;
            for (DWORD j = 0; j < limits->GroupCount; ++j)
                if (EqualSid(group.Sid, limits->Groups[j].Sid))
                    sid = group.Sid;
        }
        if (!sid && acl) {
            // Otherwise accept one unambiguous, already configured restricting
            // principal. Never grant all restricting groups or a broad alias.
            for (DWORD i = 0; i < limits->GroupCount; ++i) {
                auto candidate = limits->Groups[i].Sid;
                if (IsWellKnownSid(candidate, WinWorldSid) ||
                    IsWellKnownSid(candidate, WinAuthenticatedUserSid) ||
                    IsWellKnownSid(candidate, WinBuiltinUsersSid))
                    continue;
                for (WORD j = 0; j < acl->AceCount; ++j) {
                    void *entry = nullptr;
                    check(GetAce(acl, j, &entry), "initial object ACE");
                    auto allowed = static_cast<ACCESS_ALLOWED_ACE *>(entry);
                    if (allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && allowed->Mask &&
                        EqualSid(&allowed->SidStart, candidate)) {
                        check(!sid || EqualSid(sid, candidate), "ambiguous restricted object SID");
                        sid = candidate;
                    }
                }
            }
        }
        check(sid != nullptr, "configured restricted object SID required");
    }
    check(IsValidSid(sid) && GetLengthSid(sid) <= sizeof(state.compat_sid),
          "compatibility SID capacity");
    state.compat_sid_bytes = GetLengthSid(sid);
    memcpy(state.compat_sid, sid, state.compat_sid_bytes);
    state.object_policy_valid = 1;
    SECURITY_DESCRIPTOR namespace_descriptor{};
    check(InitializeSecurityDescriptor(&namespace_descriptor, SECURITY_DESCRIPTOR_REVISION),
          "namespace descriptor");
    check(SetSecurityDescriptorDacl(&namespace_descriptor, TRUE, acl, FALSE),
          "namespace default ACL");
    // Keep the AppContainer namespace choice independent of the selected
    // non-AppContainer restricting principal above.
    auto package_sid =
        reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer;
    // AppContainer namespaces are supplied by Windows. Restricted tokens need
    // a per-launch directory so unrelated MSYS sessions cannot precreate it
    // with a different ACL. Native intermediaries inherit the launch tag.
    wchar_t relative[object_root_chars]{};
    ULONG chars = 0;
    if (package_sid)
        check(GetAppContainerNamedObjectPath(token, nullptr, _countof(relative), relative, &chars),
              "AppContainer object namespace");
    else
        wcscpy_s(relative, L"BaseNamedObjects");
    DWORD session = 0;
    check(GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size),
          "TokenSessionId");
    auto root = L"\\Sessions\\" + std::to_wstring(session) + L"\\" + relative;
    HANDLE directory = nullptr;
    if (!package_sid) {
        wchar_t tag[32]{};
        auto count = GetEnvironmentVariableW(L"MSYS_SANDBOX_COMPAT_SESSION", tag, _countof(tag));
        check(count < _countof(tag), "inherited compatibility session");
        for (DWORD i = 0; i < count; ++i)
            check(tag[i] >= L'0' && tag[i] <= L'9', "compatibility session tag");
        auto identity = count ? std::wstring(tag) : std::to_wstring(GetCurrentProcessId());
        check(SetEnvironmentVariableW(L"MSYS_SANDBOX_COMPAT_SESSION", identity.c_str()),
              "inherit compatibility session");
        root += L"\\msys-sandbox-compat-" + identity;
        check(root.size() < object_root_chars, "namespace capacity");
        UNICODE_STRING name{static_cast<USHORT>(root.size() * sizeof(wchar_t)),
                            static_cast<USHORT>((root.size() + 1) * sizeof(wchar_t)), root.data()};
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, nullptr,
                                   &namespace_descriptor);
        check_nt(
            state.api.create_directory(&directory, STANDARD_RIGHTS_REQUIRED | 0xf, &attributes),
            "restricted compatibility namespace");
    }
    check(root.size() < object_root_chars, "namespace capacity");
    memcpy(state.object_root, root.c_str(), (root.size() + 1) * 2);
    state.root_chars = static_cast<uint32_t>(root.size());
    return directory;
}
} // namespace msys_sandbox_compat
