#include "host.h"
#include <securityappcontainer.h>

namespace msys_sandbox_compat {
HANDLE prepare_ipc_directory(AgentState &state) {
    const HANDLE token = GetCurrentProcessToken();
    alignas(TOKEN_APPCONTAINER_INFORMATION)
        BYTE package[sizeof(TOKEN_APPCONTAINER_INFORMATION) + SECURITY_MAX_SID_SIZE];
    DWORD size = 0;
    check(GetTokenInformation(token, TokenAppContainerSid, package, sizeof(package), &size),
          "TokenAppContainerSid");
    const auto package_sid =
        reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION *>(package)->TokenAppContainer;
    if (!package_sid && !IsTokenRestricted(token))
        return nullptr;

    // AppContainer namespaces are supplied by Windows. Restricted tokens need
    // a per-launch directory so unrelated MSYS sessions cannot precreate it
    // with a different ACL. The agent carries this directory within the tree.
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
    if (!package_sid)
        root += L"\\msys-sandbox-compat-" + std::to_wstring(GetCurrentProcessId());
    check(root.size() < object_root_chars, "namespace capacity");
    HANDLE directory = nullptr;
    if (!package_sid) {
        DWORD default_bytes = 0;
        GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &default_bytes);
        std::vector<BYTE> default_info(default_bytes);
        check(default_bytes && GetTokenInformation(token, TokenDefaultDacl, default_info.data(),
                                                    default_bytes, &default_bytes),
              "TokenDefaultDacl");
        const auto acl = reinterpret_cast<TOKEN_DEFAULT_DACL *>(default_info.data())->DefaultDacl;
        check(!acl || IsValidAcl(acl), "sandbox default DACL");
        SECURITY_DESCRIPTOR namespace_descriptor{};
        check(InitializeSecurityDescriptor(&namespace_descriptor, SECURITY_DESCRIPTOR_REVISION),
              "namespace descriptor");
        check(SetSecurityDescriptorDacl(&namespace_descriptor, TRUE, acl, FALSE),
              "namespace default ACL");
        UNICODE_STRING name{static_cast<USHORT>(root.size() * sizeof(wchar_t)),
                            static_cast<USHORT>((root.size() + 1) * sizeof(wchar_t)), root.data()};
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, nullptr,
                                   &namespace_descriptor);
        check_nt(
            state.api.create_directory(&directory, STANDARD_RIGHTS_REQUIRED | 0xf, &attributes),
            "restricted compatibility namespace");
    }
    memcpy(state.object_root, root.c_str(), (root.size() + 1) * 2);
    state.root_chars = static_cast<uint32_t>(root.size());
    return directory;
}
} // namespace msys_sandbox_compat
