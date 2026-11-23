#include "msys_sandbox_compat/object_security.h"
#include <intrin.h>
#include <string.h>

namespace msys_sandbox_compat {
namespace {
ObjectSecurityContext ordinary_context{};

ULONG sid_size(const SID *sid) {
    return static_cast<ULONG>(offsetof(SID, SubAuthority) +
                              sid->SubAuthorityCount * sizeof(DWORD));
}

bool equal_bytes(const BYTE *a, const BYTE *b, size_t size) {
    for (size_t i = 0; i < size; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

bool equal_sid(const SID *a, const SID *b) {
    return a->SubAuthorityCount == b->SubAuthorityCount &&
           equal_bytes(reinterpret_cast<const BYTE *>(a), reinterpret_cast<const BYTE *>(b),
                       sid_size(a));
}

bool broad_sid(const SID *sid) {
    const SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    const auto authority = sid->IdentifierAuthority.Value;
    if (sid->SubAuthorityCount == 1 && equal_bytes(authority, world.Value, sizeof(world.Value)))
        return sid->SubAuthority[0] == SECURITY_WORLD_RID;
    if (!equal_bytes(authority, nt.Value, sizeof(nt.Value)))
        return false;
    return (sid->SubAuthorityCount == 1 && sid->SubAuthority[0] == SECURITY_AUTHENTICATED_USER_RID) ||
           (sid->SubAuthorityCount == 2 && sid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID &&
            sid->SubAuthority[1] == DOMAIN_ALIAS_RID_USERS);
}

NTSTATUS default_restricting_sid(const NativeApi &api, const TOKEN_GROUPS &limits, const SID *&sid) {
    ULONG bytes = 0;
    auto status = api.query_token(current_process_token(), TokenDefaultDacl, nullptr, 0, &bytes);
    if (status != status_buffer_too_small)
        return status;
    NativeBuffer storage(api, bytes);
    if (!storage)
        return status_unsuccessful;
    auto policy = storage.as<TOKEN_DEFAULT_DACL>();
    status = api.query_token(current_process_token(), TokenDefaultDacl, policy, bytes, &bytes);
    if (status < 0 || !policy->DefaultDacl)
        return status;

    const auto acl = policy->DefaultDacl;
    auto ace = reinterpret_cast<const BYTE *>(acl + 1);
    for (WORD i = 0; i < acl->AceCount; ++i) {
        const auto allow = reinterpret_cast<const ACCESS_ALLOWED_ACE *>(ace);
        ace += allow->Header.AceSize;
        if (allow->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || !allow->Mask)
            continue;
        for (DWORD j = 0; j < limits.GroupCount; ++j) {
            const auto candidate = static_cast<const SID *>(limits.Groups[j].Sid);
            if (broad_sid(candidate) ||
                !equal_sid(reinterpret_cast<const SID *>(&allow->SidStart), candidate))
                continue;
            if (sid && !equal_sid(sid, candidate))
                return status_not_supported;
            sid = candidate;
        }
    }
    return status_success;
}

NTSTATUS read_restricting_sid(const NativeApi &api, ObjectSecurityContext &context) {
    TOKEN_GROUPS empty{};
    ULONG bytes = 0;
    auto status = api.query_token(current_process_token(), TokenRestrictedSids, &empty,
                                  sizeof(empty), &bytes);
    if (status != status_buffer_too_small)
        return status;
    NativeBuffer restricted(api, bytes);
    if (!restricted)
        return status_unsuccessful;
    const auto limits = restricted.as<TOKEN_GROUPS>();
    status = api.query_token(current_process_token(), TokenRestrictedSids, limits, bytes, &bytes);
    if (status < 0)
        return status;

    status = api.query_token(current_process_token(), TokenGroups, nullptr, 0, &bytes);
    if (status != status_buffer_too_small)
        return status;
    NativeBuffer groups(api, bytes);
    if (!groups)
        return status_unsuccessful;
    const auto enabled = groups.as<TOKEN_GROUPS>();
    status = api.query_token(current_process_token(), TokenGroups, enabled, bytes, &bytes);
    if (status < 0)
        return status;

    const SID *sid = nullptr;
    for (DWORD i = 0; i < enabled->GroupCount && !sid; ++i) {
        const auto &group = enabled->Groups[i];
        if ((group.Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID ||
            !(group.Attributes & SE_GROUP_ENABLED) || (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
            continue;
        for (DWORD j = 0; j < limits->GroupCount; ++j)
            if (equal_sid(static_cast<const SID *>(group.Sid), static_cast<const SID *>(limits->Groups[j].Sid))) {
                sid = static_cast<const SID *>(group.Sid);
                break;
            }
    }
    if (!sid) {
        status = default_restricting_sid(api, *limits, sid);
        if (status < 0)
            return status;
        if (!sid)
            return status_not_supported;
    }
    context.compat_sid_bytes = sid_size(sid);
    memcpy(context.compat_sid, sid, context.compat_sid_bytes);
    return status_success;
}

NTSTATUS read_context(const NativeApi &api, ObjectSecurityContext &context) {
    alignas(TOKEN_APPCONTAINER_INFORMATION)
        BYTE package[sizeof(TOKEN_APPCONTAINER_INFORMATION) + SECURITY_MAX_SID_SIZE];
    ULONG bytes = 0;
    auto status = api.query_token(current_process_token(), TokenAppContainerSid, package,
                                  sizeof(package), &bytes);
    if (status < 0)
        return status;
    const auto app = static_cast<const SID *>(
        reinterpret_cast<const TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer);
    if (app) {
        context.compat_sid_bytes = sid_size(app);
        memcpy(context.compat_sid, app, context.compat_sid_bytes);
    } else {
        status = read_restricting_sid(api, context);
        if (status < 0 || !context.compat_sid_bytes)
            return status;
    }

    alignas(TOKEN_USER) BYTE user[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    status = api.query_token(current_process_token(), TokenUser, user, sizeof(user), &bytes);
    if (status < 0)
        return status;
    const auto sid = static_cast<const SID *>(reinterpret_cast<const TOKEN_USER *>(user)->User.Sid);
    context.user_sid_bytes = sid_size(sid);
    memcpy(context.user_sid, sid, context.user_sid_bytes);
    return status_success;
}
} // namespace

NTSTATUS get_object_security(AgentState &state, const ObjectSecurityContext *&context) {
    auto cached = state.local.object_security;
    _ReadBarrier();
    if (cached) {
        context = static_cast<const ObjectSecurityContext *>(cached);
        return status_success;
    }

    ObjectSecurityContext current{};
    const auto status = read_context(state.api, current);
    if (status < 0)
        return status;
    // Only the process owns this data. A concurrent first caller can publish
    // its result first; the losing allocation is then freed automatically.
    NativeBuffer storage(state.api, current.compat_sid_bytes ? sizeof(current) : 0);
    auto identity = &ordinary_context;
    if (current.compat_sid_bytes) {
        if (!storage)
            return status_unsuccessful;
        identity = storage.as<ObjectSecurityContext>();
        *identity = current;
    }
    cached = _InterlockedCompareExchangePointer(&state.local.object_security, identity, nullptr);
    if (!cached)
        storage.release();
    context = cached ? static_cast<const ObjectSecurityContext *>(cached) : identity;
    return status_success;
}
} // namespace msys_sandbox_compat
