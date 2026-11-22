#include "agent_runtime.h"

#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/object_security.h"
#include <intrin.h>

using namespace msys_sandbox_compat;

extern "C" {
__declspec(dllexport) AgentState g_agent_state{};
extern __declspec(dllexport) const uint32_t g_agent_abi = agent_abi;
__declspec(dllexport) uintptr_t g_native_chkstk = 0;
#pragma section(".thunks", read, execute)
__declspec(allocate(".thunks"))
__declspec(dllexport) BYTE g_agent_thunks[hook_count][hook_trampoline_bytes] = {{0x90}};
}


void register_unwind() {
    auto &state = g_agent_state;
    if (state.local.unwind_registered ||
        _InterlockedCompareExchange(&state.local.unwind_registered, 1, 0))
        return;
    auto pe = PeView(reinterpret_cast<void *>(state.self_base), state.self_size).headers();
    auto &table = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    state.api.add_function_table(
        reinterpret_cast<PRUNTIME_FUNCTION>(state.self_base + table.VirtualAddress),
        table.Size / sizeof(RUNTIME_FUNCTION), state.self_base);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI
hook_process(PHANDLE process, PHANDLE thread, ACCESS_MASK process_access, ACCESS_MASK thread_access,
             POBJECT_ATTRIBUTES process_attributes, POBJECT_ATTRIBUTES thread_attributes,
             ULONG process_flags, ULONG thread_flags, PRTL_USER_PROCESS_PARAMETERS parameters,
             void *create_info, void *attributes) {
    auto &state = g_agent_state;
    register_unwind();
    PolicyGuard guard(state);
    if (state.native_relay && !state.plain_context) {
        auto permitted = check_object_policy(state.api, reinterpret_cast<HANDLE>(-4), state);
        if (permitted < 0) {
            if (process)
                *process = nullptr;
            if (thread)
                *thread = nullptr;
            return permitted;
        }
    }
    bool owns_reservation = false;
    NTSTATUS status = status_success;
    auto create = [&](void *creation_attributes) {
        return state.api.create_process(
            process, thread, process_access, thread_access, process_attributes, thread_attributes,
            process_flags, thread_flags | thread_create_suspended, parameters, create_info,
            creation_attributes);
    };
    if (state.enabled(Module::heap_window)) {
        agent_log(state, "child heap preflight");
        HeapReservation reserve(state.api, attributes);
        status = create(reserve.attributes());
        owns_reservation = reserve.attributes() != attributes;
    } else
        status = create(attributes);
    if (status < 0)
        return status;
    bool related = false;
    auto prepared = status_success;
    if (!state.native_relay || owns_reservation || state.trace ||
        (!state.plain_context && state.enabled(Module::process_dacl)))
        prepared = identify_process(state.api, *process, related);
    if (owns_reservation && prepared >= 0 && !related)
        prepared = status_invalid_image;
    if (prepared < 0) {
        if (owns_reservation || state.native_relay || related)
            goto failed;
        agent_log(state, "child classification unavailable; left uninstrumented",
                  static_cast<ULONG>(prepared));
    } else if (related || state.native_relay) {
        agent_log(state, "child modules", state.effective_modules(related));
        if (state.native_relay) {
            prepared = check_child_context(state.api, *process, state);
            if (prepared < 0)
                goto failed;
        }
        if (related) {
            prepared = adapt_child_objects(*process, *thread, state);
            if (prepared < 0)
                goto failed;
        }
        prepared = clone_agent(*process, state);
        if (prepared < 0)
            goto failed;
        agent_log(state, related ? "injected MSYS child" : "injected native relay",
                  reinterpret_cast<ULONG_PTR>(*process));
    } else {
        agent_log(state, "native child left uninstrumented", reinterpret_cast<ULONG_PTR>(*process));
    }
    if (owns_reservation) {
        prepared = release_heap_reservation(state.api, *process, state);
        if (prepared < 0)
            goto failed;
    }
    if (!(thread_flags & thread_create_suspended)) {
        prepared = state.api.resume(*thread, nullptr);
        if (prepared < 0)
            goto failed;
    }
    return status;

failed:
    agent_log(state, "child preparation failed", static_cast<ULONG>(prepared));
    state.api.terminate(*process, prepared);
    state.api.close(*thread);
    state.api.close(*process);
    *thread = nullptr;
    *process = nullptr;
    return prepared;
}
