#include "msys_sandbox_compat/object_security.h"
#include <sddl.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
using namespace msys_sandbox_compat;
namespace msys_sandbox_compat {
void agent_log(const AgentState &, const char *, ULONG_PTR) {}
} // namespace msys_sandbox_compat
static int failures = 0;
static void expect(bool ok, const char *name) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        ++failures;
}
static NativeApi api() {
    NativeApi result{};
    auto module = GetModuleHandleW(L"ntdll.dll");
#define BIND(field, name)                                                                          \
    result.field = reinterpret_cast<decltype(result.field)>(GetProcAddress(module, name))
    BIND(allocate, "NtAllocateVirtualMemory");
    BIND(free, "NtFreeVirtualMemory");
    BIND(read, "NtReadVirtualMemory");
    BIND(query_token, "NtQueryInformationToken");
#undef BIND
    return result;
}
static PACL dacl(PSECURITY_DESCRIPTOR sd) {
    PACL acl = nullptr;
    BOOL present = FALSE, inherited = FALSE;
    GetSecurityDescriptorDacl(sd, &present, &acl, &inherited);
    return acl;
}
int main() {
    auto native = api();
    AgentState state{};
    BYTE user[1024]{};
    DWORD returned = 0;
    GetTokenInformation(GetCurrentProcessToken(), TokenUser, user, sizeof(user), &returned);
    auto sid = reinterpret_cast<TOKEN_USER *>(user)->User.Sid;
    state.user_sid_bytes = GetLengthSid(sid);
    memcpy(state.user_sid, sid, state.user_sid_bytes);
    PSID compat = nullptr;
    ConvertStringSidToSidW(L"S-1-15-2-11223344-55667788", &compat);
    state.compat_sid_bytes = GetLengthSid(compat);
    memcpy(state.compat_sid, compat, state.compat_sid_bytes);
    LPWSTR user_text = nullptr;
    ConvertSidToStringSidW(sid, &user_text);
    std::wstring user_sid(user_text);
    LocalFree(user_text);
    auto check_acl = [&](const wchar_t *suffix, DWORD expected, const char *name) {
        auto sddl = std::wstring(L"D:P") + suffix;
        size_t where = 0;
        while ((where = sddl.find(L"USER", where)) != std::wstring::npos) {
            sddl.replace(where, 4, user_sid);
            where += user_sid.size();
        }
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), 1, &sd, nullptr)) {
            expect(false, name);
            return;
        }
        auto input = dacl(sd);
        std::vector<BYTE> before(input->AclSize);
        memcpy(before.data(), input, input->AclSize);
        SecurityAdaptation adapted(native);
        auto status = adapted.acl(input, state);
        auto output = adapted.adapted_acl();
        bool pass = status >= 0 && !memcmp(input, before.data(), before.size());
        if (expected) {
            pass = pass && output && output->AceCount == input->AceCount + 1;
            for (WORD i = 0; pass && i < input->AceCount; ++i) {
                void *a = nullptr, *b = nullptr;
                GetAce(input, i, &a);
                GetAce(output, i, &b);
                pass = !memcmp(a, b, reinterpret_cast<ACE_HEADER *>(a)->AceSize);
            }
            if (pass) {
                void *last = nullptr;
                GetAce(output, output->AceCount - 1, &last);
                auto ace = static_cast<ACCESS_ALLOWED_ACE *>(last);
                pass = ace->Mask == expected && !ace->Header.AceFlags &&
                       EqualSid(&ace->SidStart, compat);
            }
            if (pass) {
                SecurityAdaptation repeat(native);
                pass = repeat.acl(output, state) >= 0 && !repeat.adapted_acl();
            }
        } else
            pass = pass && !output;
        expect(pass, name);
        LocalFree(sd);
    };
    check_acl(L"(A;;GA;;;USER)(A;;GA;;;SY)", GENERIC_ALL,
              "direct user; preserve original ACEs; idempotent");
    check_acl(L"(A;;0x8;;;USER)(A;;0x4;;;WD)", 12,
              "combine actual enabled-group grants with user rights");
    check_acl(L"(A;;0x8;;;USER)(A;;0x4;;;S-1-15-2-11223344-55667788)", 8,
              "append only missing trustee mask");
    check_acl(L"(A;;GA;;;SY)", 0, "SYSTEM-only remains unchanged");
    check_acl(L"(D;;0x8;;;USER)(A;;GA;;;USER)", 0, "user deny remains unchanged");
    check_acl(L"(D;;0x8;;;WD)(A;;GA;;;USER)", 0, "group deny remains unchanged");
    check_acl(L"(A;OICI;GA;;;USER)", 0, "inheritance-bearing input remains unchanged");
    check_acl(L"", 0, "empty ACL remains empty");
    SecurityAdaptation null_acl(native);
    bool null_ok = null_acl.acl(nullptr, state) >= 0 && null_acl.adapted_acl() &&
                   null_acl.adapted_acl()->AceCount == 2;
    if (null_ok) {
        void *entry = nullptr;
        GetAce(null_acl.adapted_acl(), 0, &entry);
        auto first = static_cast<ACCESS_ALLOWED_ACE *>(entry);
        null_ok = first->Mask == GENERIC_ALL && IsWellKnownSid(&first->SidStart, WinWorldSid);
        GetAce(null_acl.adapted_acl(), 1, &entry);
        auto second = static_cast<ACCESS_ALLOWED_ACE *>(entry);
        null_ok = null_ok && second->Mask == GENERIC_ALL && EqualSid(&second->SidStart, compat);
    }
    expect(null_ok, "NULL ACL retains unrestricted intent and gains explicit trustee");
    auto sddl = L"O:" + user_sid + L"G:SYD:P(A;;0x8;;;" + user_sid + L")S:(ML;;NW;;;LW)";
    PSECURITY_DESCRIPTOR original = nullptr;
    bool valid = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), 1, &original,
                                                                      nullptr) != FALSE;
    if (valid) {
        SecurityAdaptation adapted(native);
        auto status = adapted.descriptor(original, state);
        auto output = adapted.adapted_descriptor();
        PSID a = nullptr, b = nullptr;
        BOOL flag = FALSE;
        GetSecurityDescriptorOwner(original, &a, &flag);
        if (output)
            GetSecurityDescriptorOwner(output, &b, &flag);
        bool pass = status >= 0 && output && EqualSid(a, b);
        GetSecurityDescriptorGroup(original, &a, &flag);
        if (output)
            GetSecurityDescriptorGroup(output, &b, &flag);
        pass = pass && EqualSid(a, b);
        PACL sa = nullptr, sb = nullptr;
        BOOL present = FALSE;
        GetSecurityDescriptorSacl(original, &present, &sa, &flag);
        if (output)
            GetSecurityDescriptorSacl(output, &present, &sb, &flag);
        pass = pass && sa && sb && sa->AclSize == sb->AclSize && !memcmp(sa, sb, sa->AclSize);
        SECURITY_DESCRIPTOR_CONTROL ca = 0, cb = 0;
        DWORD revision = 0;
        GetSecurityDescriptorControl(original, &ca, &revision);
        if (output)
            GetSecurityDescriptorControl(output, &cb, &revision);
        pass = pass && (ca & ~SE_SELF_RELATIVE) == cb;
        expect(pass, "self-relative input preserves owner/group/SACL/control");
        SECURITY_DESCRIPTOR absolute{};
        InitializeSecurityDescriptor(&absolute, 1);
        absolute.Owner = sid;
        absolute.Group = compat;
        absolute.Dacl = dacl(original);
        absolute.Sacl = sa;
        absolute.Control = SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SACL_PRESENT;
        SecurityAdaptation second(native);
        status = second.descriptor(&absolute, state);
        output = second.adapted_descriptor();
        expect(status >= 0 && output && static_cast<SECURITY_DESCRIPTOR *>(output)->Owner == sid &&
                   static_cast<SECURITY_DESCRIPTOR *>(output)->Group == compat &&
                   static_cast<SECURITY_DESCRIPTOR *>(output)->Sacl == sa &&
                   static_cast<SECURITY_DESCRIPTOR *>(output)->Control == absolute.Control,
               "absolute SD fields preserved");
        LocalFree(original);
    } else
        expect(false, "construct owner/group/SACL fixture");
    ACL invalid{};
    invalid.AclSize = sizeof(invalid);
    SecurityAdaptation bad(native);
    expect(bad.acl(&invalid, state) >= 0 && !bad.adapted_acl(), "invalid ACL is not repaired");
    LocalFree(compat);
    return failures ? 1 : 0;
}
