#include "agent_runtime.h"

#include "msys_sandbox_compat/object_security.h"

using namespace msys_sandbox_compat;

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_set_token(HANDLE token,
                                                               TOKEN_INFORMATION_CLASS kind,
                                                               void *information, ULONG bytes) {
    auto &state = g_agent_state;
    register_unwind();
    if (kind != TokenDefaultDacl || !information || bytes != sizeof(TOKEN_DEFAULT_DACL))
        return state.api.set_token(token, kind, information, bytes);
    HANDLE primary = nullptr;
    if (state.api.open_token(current_process(), TOKEN_QUERY, &primary) < 0)
        return state.api.set_token(token, kind, information, bytes);
    auto same = state.api.compare_objects(token, primary);
    state.api.close(primary);
    if (same != 0)
        return state.api.set_token(token, kind, information, bytes);
    PolicyGuard guard(state);
    TOKEN_DEFAULT_DACL input{};
    if (state.api.read(current_process(), information, &input, sizeof(input), nullptr) < 0)
        return state.api.set_token(token, kind, information, bytes);
    SecurityAdaptation adapted(state.api);
    auto status = adapted.acl(input.DefaultDacl, state);
    if (status < 0)
        return status;
    TOKEN_DEFAULT_DACL replacement{adapted.adapted_acl()};
    status =
        state.api.set_token(token, kind, adapted.adapted_acl() ? &replacement : information, bytes);
    if (status >= 0 && state.native_relay)
        remember_object_policy(state);
    return status;
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI
hook_set_security(HANDLE object, SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor) {
    auto &state = g_agent_state;
    register_unwind();
    if (object != current_process() || information != DACL_SECURITY_INFORMATION)
        return state.api.set_security(object, information, descriptor);

    // Cold startup sets a process DACL separately from the token default DACL.
    SecurityAdaptation adapted(state.api);
    auto status = adapted.descriptor(descriptor, state);
    if (status < 0)
        return status;
    if (auto replacement = adapted.adapted_descriptor())
        descriptor = replacement;
    return state.api.set_security(object, information, descriptor);
}
