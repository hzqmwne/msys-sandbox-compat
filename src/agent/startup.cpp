#include "agent_runtime.h"
#include <intrin.h>
#include <string.h>

using namespace msys_sandbox_compat;

namespace {
NTSTATUS initialize_child(AgentState &state, BYTE *peb, CONTEXT &saved) {
    auto &api = state.api;
    const auto process = current_process();
    uintptr_t base = 0;
    memcpy(&base, peb + 0x10, sizeof(base));
    ImageRecord image{};
    bool related = false;
    auto status = identify_executable(api, process, reinterpret_cast<void *>(base), image, related);
    if (status < 0) {
        bool wow64 = false;
        if (!state.native_relay || query_wow64_process(api, process, wow64) < 0 || !wow64)
            return status;
        // WoW64 calls the native system entry from its AMD64 thunk.
    }

    const auto modules = state.effective_modules(related);
    if (modules & bit(Module::exe_placement)) {
        status = prepare_exe_layout(state, peb, saved, base, image);
        if (status < 0)
            return status;
        if ((modules & bit(Module::propagation)) && !state.local.image.image_base)
            capture_parent_image(api, base, state.local.image);
    }
    const auto installed = selected_hooks(modules);
    if (!installed)
        return status_success;

    void *thunks = g_agent_thunks;
    SIZE_T bytes = sizeof(g_agent_thunks);
    ULONG old = 0, ignored = 0;
    status = api.protect(process, &thunks, &bytes, PAGE_READWRITE, &old);
    if (status < 0)
        return status;
    const auto originals = bind_original_calls(state, installed);
    status = install_hooks(api, process, state, installed);
    const auto restored = api.protect(process, &thunks, &bytes, old, &ignored);
    if (status < 0 || restored < 0)
        return status < 0 ? status : restored;
    state.api = originals;
    return status_success;
}
} // namespace

extern "C" __declspec(dllexport) void NTAPI start_agent(PCONTEXT saved, void *arg2, void *arg3,
                                                        void *arg4) {
    auto &state = g_agent_state;
    auto &api = state.api;
    const auto process = current_process();
    const auto &slot = state.hooks[static_cast<size_t>(HookId::startup)];
    auto entry = reinterpret_cast<void *>(slot.target);

    // This runs on the initial thread before the original loader body. Restore
    // the entry first so Windows can use it normally for later threads.
    auto status = replace_entry(api, process, entry, state.local.loader_entry);
    if (status >= 0)
        status = api.flush_code(process, entry, hook_patch_bytes);
    if (status >= 0 && saved)
        status = initialize_child(state, reinterpret_cast<BYTE *>(__readgsqword(0x60)), *saved);
    else if (status >= 0)
        status = status_invalid_image;
    if (status < 0) {
        api.terminate(process, status);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    reinterpret_cast<decltype(&start_agent)>(entry)(saved, arg2, arg3, arg4);
}
