#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/native_buffer.h"
#include <initializer_list>

namespace msys_sandbox_compat {
namespace {
bool same_bytes(const void *left, const void *right, size_t count) {
    auto a = static_cast<const BYTE *>(left);
    auto b = static_cast<const BYTE *>(right);
    for (size_t i = 0; i < count; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}
bool same_sid(PSID left, PSID right) {
    if (!left || !right)
        return left == right;
    auto a = static_cast<SID *>(left);
    auto b = static_cast<SID *>(right);
    return a->SubAuthorityCount == b->SubAuthorityCount &&
           same_bytes(a, b, 8 + 4 * a->SubAuthorityCount);
}
bool same_groups(const TOKEN_GROUPS *a, const TOKEN_GROUPS *b) {
    if (a->GroupCount != b->GroupCount)
        return false;
    for (DWORD i = 0; i < a->GroupCount; ++i)
        if (a->Groups[i].Attributes != b->Groups[i].Attributes ||
            !same_sid(a->Groups[i].Sid, b->Groups[i].Sid))
            return false;
    return true;
}
bool same_access_flags(const NativeApi &api, HANDLE process, HANDLE child, ULONG left, ULONG right) {
    constexpr ULONG token_virtualize_enabled = 0x0400;
    const auto difference = left ^ right;
    if (!difference)
        return true;
    if (difference != token_virtualize_enabled)
        return false;
    bool parent_wow64 = false, child_wow64 = false;
    query_wow64_process(api, current_process(), parent_wow64);
    query_wow64_process(api, process, child_wow64);
    if (!parent_wow64 && !child_wow64)
        return false;
    // Windows can change this per-application UAC flag when creating a legacy
    // x86 child or leaving WoW64. Confirm it with the public token information class.
    ULONG parent_enabled = 0, child_enabled = 0, bytes = 0;
    return api.query_token(reinterpret_cast<HANDLE>(-4), TokenVirtualizationEnabled, &parent_enabled,
                           sizeof(parent_enabled), &bytes) >= 0 &&
           api.query_token(child, TokenVirtualizationEnabled, &child_enabled,
                           sizeof(child_enabled), &bytes) >= 0 &&
           parent_enabled != child_enabled;
}

bool same_token_field(const NativeApi &api, HANDLE process, HANDLE child,
                      TOKEN_INFORMATION_CLASS kind, void *left, void *right) {
    switch (kind) {
    case TokenUser:
    case TokenIntegrityLevel: {
        auto a = static_cast<SID_AND_ATTRIBUTES *>(left);
        auto b = static_cast<SID_AND_ATTRIBUTES *>(right);
        return a->Attributes == b->Attributes && same_sid(a->Sid, b->Sid);
    }
    case TokenOwner:
    case TokenPrimaryGroup:
    case TokenAppContainerSid:
        return same_sid(*static_cast<PSID *>(left), *static_cast<PSID *>(right));
    case TokenGroups:
    case TokenRestrictedSids:
    case TokenCapabilities:
        return same_groups(static_cast<TOKEN_GROUPS *>(left), static_cast<TOKEN_GROUPS *>(right));
    case TokenPrivileges: {
        auto a = static_cast<TOKEN_PRIVILEGES *>(left);
        auto b = static_cast<TOKEN_PRIVILEGES *>(right);
        if (a->PrivilegeCount != b->PrivilegeCount)
            return false;
        for (DWORD i = 0; i < a->PrivilegeCount; ++i) {
            auto &x = a->Privileges[i];
            auto &y = b->Privileges[i];
            if (x.Luid.LowPart != y.Luid.LowPart || x.Luid.HighPart != y.Luid.HighPart ||
                ((x.Attributes ^ y.Attributes) & ~SE_PRIVILEGE_USED_FOR_ACCESS))
                return false;
        }
        return true;
    }
    case TokenStatistics: {
        auto a = static_cast<TOKEN_STATISTICS *>(left);
        auto b = static_cast<TOKEN_STATISTICS *>(right);
        return a->AuthenticationId.LowPart == b->AuthenticationId.LowPart &&
               a->AuthenticationId.HighPart == b->AuthenticationId.HighPart &&
               a->TokenType == b->TokenType;
    }
    case TokenAccessInformation:
        return same_access_flags(api, process, child,
                                 static_cast<TOKEN_ACCESS_INFORMATION *>(left)->Flags,
                                 static_cast<TOKEN_ACCESS_INFORMATION *>(right)->Flags);
    default:
        return *static_cast<DWORD *>(left) == *static_cast<DWORD *>(right);
    }
}
} // namespace

NTSTATUS check_child_context(const NativeApi &api, HANDLE process, const AgentState &state) {
    // A relay must not carry the old sandbox's namespace/ACL into a different
    // token context. Keep the existing per-query capacity for token groups.
    constexpr ULONG capacity = 8200;
    NativeBuffer storage(api, 2 * capacity);
    if (!storage)
        return status_unsuccessful;
    HANDLE child = nullptr;
    auto status = api.open_token(process, TOKEN_QUERY, &child);
    if (status < 0)
        return status;
    void *left = storage.as<BYTE>();
    void *right = storage.as<BYTE>() + capacity;
    for (auto kind : {TokenUser, TokenGroups, TokenRestrictedSids, TokenPrivileges, TokenOwner,
                      TokenPrimaryGroup, TokenIntegrityLevel, TokenAppContainerSid,
                      TokenCapabilities, TokenMandatoryPolicy, TokenSessionId, TokenUIAccess,
                      TokenSandBoxInert, TokenStatistics, TokenAccessInformation}) {
        ULONG returned = 0;
        status = api.query_token(reinterpret_cast<HANDLE>(-4), kind, left, capacity, &returned);
        if (status < 0)
            break;
        status = api.query_token(child, kind, right, capacity, &returned);
        if (status < 0)
            break;
        if (!same_token_field(api, process, child, kind, left, right)) {
            agent_log(state, "relay token context differs", kind);
            status = status_access_denied;
            break;
        }
    }
    api.close(child);
    return status;
}
} // namespace msys_sandbox_compat
