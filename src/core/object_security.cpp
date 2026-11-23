#include "msys_sandbox_compat/object_security.h"
#include "msys_sandbox_compat/native_buffer.h"
#include <string.h>

namespace msys_sandbox_compat {
namespace {
bool same_sid(const void *left, const void *right, size_t bytes) {
    auto a = static_cast<const BYTE *>(left), b = static_cast<const BYTE *>(right);
    for (size_t i = 0; i < bytes; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}
} // namespace

SecurityAdaptation::~SecurityAdaptation() {
    if (memory_) {
        SIZE_T bytes = 0;
        api_.free(current_process(), &memory_, &bytes, MEM_RELEASE);
    }
}

NTSTATUS SecurityAdaptation::acl(PACL input, const AgentState &state) {
    if (!state.compat_sid_bytes || !state.user_sid_bytes)
        return status_success;
    if (!input) {
        // A NULL DACL grants everyone access, but an explicit lowbox trustee is
        // still needed for these shared objects. Keep that unrestricted intent
        // rather than replacing it with a user-only template. Empty != NULL.
        const BYTE world[] = {SID_REVISION, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
        SIZE_T bytes = sizeof(ACL) + 8 + sizeof(world) + 8 + state.compat_sid_bytes;
        const auto acl_bytes = bytes;
        auto status = api_.allocate(current_process(), &memory_, 0, &bytes,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status < 0)
            return status;
        auto acl = static_cast<ACL *>(memory_);
        acl->AclRevision = ACL_REVISION;
        acl->AclSize = static_cast<WORD>(acl_bytes);
        acl->AceCount = 2;
        auto first = reinterpret_cast<ACCESS_ALLOWED_ACE *>(acl + 1);
        first->Header = {ACCESS_ALLOWED_ACE_TYPE, 0, static_cast<WORD>(8 + sizeof(world))};
        first->Mask = GENERIC_ALL;
        memcpy(&first->SidStart, world, sizeof(world));
        auto second = reinterpret_cast<ACCESS_ALLOWED_ACE *>(reinterpret_cast<BYTE *>(first) +
                                                             first->Header.AceSize);
        second->Header = {ACCESS_ALLOWED_ACE_TYPE, 0,
                          static_cast<WORD>(8 + state.compat_sid_bytes)};
        second->Mask = GENERIC_ALL;
        memcpy(&second->SidStart, state.compat_sid, state.compat_sid_bytes);
        return status_success;
    }
    ACL header{};
    // Invalid/unsupported input goes unchanged to the original API, which owns
    // validation and its error semantics. Never turn a bad ACL into a good one.
    if (api_.read(current_process(), input, &header, sizeof(header), nullptr) < 0 ||
        header.AclRevision != ACL_REVISION || header.AclSize < sizeof(ACL) || !header.AceCount)
        return status_success;
    const size_t extra = 8 + state.compat_sid_bytes;
    if (header.AclSize > 0xffff - extra)
        return status_success;
    NativeBuffer copy(api_, header.AclSize + extra);
    if (!copy)
        return status_unsuccessful;
    auto data = copy.as<BYTE>();
    if (api_.read(current_process(), input, data, header.AclSize, nullptr) < 0)
        return status_success;
    auto original = reinterpret_cast<ACL *>(data);
    if (original->AclRevision != header.AclRevision || original->AclSize != header.AclSize ||
        original->AceCount != header.AceCount)
        return status_success;
    NativeBuffer context(api_, 8192);
    if (!context)
        return status_unsuccessful;
    ULONG returned = 0;
    auto queried = api_.query_token(reinterpret_cast<HANDLE>(-4), TokenGroups, context.as<BYTE>(),
                                    8192, &returned);
    if (queried < 0)
        return queried;
    auto groups = context.as<TOKEN_GROUPS>();
    ACCESS_MASK user_mask = 0, compat_mask = 0;
    size_t used = sizeof(ACL);
    for (WORD index = 0; index < header.AceCount; ++index) {
        if (used + sizeof(ACE_HEADER) > header.AclSize)
            return status_success;
        auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE *>(data + used);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags ||
            ace->Header.AceSize < 16 || (ace->Header.AceSize & 3) ||
            used + ace->Header.AceSize > header.AclSize) {
            agent_log(state, "object ACL unsupported ACE type/flags",
                      ace->Header.AceType | (ace->Header.AceFlags << 8));
            return status_success;
        }
        auto sid = reinterpret_cast<SID *>(&ace->SidStart);
        size_t sid_bytes = 8 + size_t(sid->SubAuthorityCount) * 4;
        if (sid->Revision != SID_REVISION || sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
            sid_bytes + 8 != ace->Header.AceSize)
            return status_success;
        bool applies =
            sid_bytes == state.user_sid_bytes && same_sid(sid, state.user_sid, sid_bytes);
        for (DWORD group = 0; group < groups->GroupCount && !applies; ++group) {
            auto &entry = groups->Groups[group];
            auto member = static_cast<SID *>(entry.Sid);
            if ((entry.Attributes & SE_GROUP_ENABLED) &&
                !(entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
                member->SubAuthorityCount == sid->SubAuthorityCount &&
                same_sid(sid, member, sid_bytes))
                applies = true;
        }
        if (applies)
            user_mask |= ace->Mask;
        if (sid_bytes == state.compat_sid_bytes && same_sid(sid, state.compat_sid, sid_bytes))
            compat_mask |= ace->Mask;
        used += ace->Header.AceSize;
    }
    auto missing = user_mask & ~compat_mask;
    if (!missing || header.AceCount == 0xffff) {
        if (!user_mask)
            agent_log(state, "object ACL has no user or enabled-group grant");
        return status_success;
    }
    memory_ = copy.release();
    auto result = static_cast<ACL *>(memory_);
    auto added = reinterpret_cast<ACCESS_ALLOWED_ACE *>(static_cast<BYTE *>(memory_) + used);
    added->Header = {ACCESS_ALLOWED_ACE_TYPE, 0, static_cast<WORD>(extra)};
    added->Mask = missing;
    memcpy(&added->SidStart, state.compat_sid, state.compat_sid_bytes);
    result->AclSize = static_cast<WORD>(used + extra);
    ++result->AceCount;
    return status_success;
}

NTSTATUS SecurityAdaptation::descriptor(PSECURITY_DESCRIPTOR input, const AgentState &state) {
    if (!input)
        return status_success;
    SECURITY_DESCRIPTOR_RELATIVE relative{};
    if (api_.read(current_process(), input, &relative, sizeof(relative), nullptr) < 0 ||
        relative.Revision != SECURITY_DESCRIPTOR_REVISION || !(relative.Control & SE_DACL_PRESENT))
        return status_success;
    if (relative.Control & SE_SELF_RELATIVE) {
        auto base = static_cast<BYTE *>(input);
        descriptor_.Revision = relative.Revision;
        descriptor_.Sbz1 = relative.Sbz1;
        descriptor_.Control = relative.Control & ~SE_SELF_RELATIVE;
        descriptor_.Owner = relative.Owner ? base + relative.Owner : nullptr;
        descriptor_.Group = relative.Group ? base + relative.Group : nullptr;
        descriptor_.Sacl = relative.Sacl ? reinterpret_cast<ACL *>(base + relative.Sacl) : nullptr;
        descriptor_.Dacl = relative.Dacl ? reinterpret_cast<ACL *>(base + relative.Dacl) : nullptr;
    } else if (api_.read(current_process(), input, &descriptor_, sizeof(descriptor_), nullptr) <
               0) {
        return status_success;
    }
    auto status = acl(descriptor_.Dacl, state);
    if (status >= 0 && memory_)
        descriptor_.Dacl = adapted_acl();
    return status;
}

} // namespace msys_sandbox_compat
