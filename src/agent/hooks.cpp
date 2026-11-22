#include "agent_runtime.h"

#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/object_security.h"
#include <intrin.h>

using namespace msys_sandbox_compat;

extern "C" {
__declspec(dllexport) AgentState g_agent_state{};
__declspec(dllexport) uintptr_t g_native_chkstk = 0;
#pragma section(".thunks", read, execute)
__declspec(allocate(".thunks"))
__declspec(dllexport) BYTE g_agent_thunks[hook_count][hook_trampoline_bytes] = {{0x90}};
}


void register_unwind() {
    auto &state = g_agent_state;
    if (_InterlockedCompareExchange(&state.local.unwind_registered, 1, 0))
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
    if (state.native_relay) {
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
    {
        HeapReservation reserve(state.api, attributes);
        status = state.api.create_process(
            process, thread, process_access, thread_access, process_attributes, thread_attributes,
            process_flags, thread_flags | thread_create_suspended, parameters, create_info,
            reserve.attributes());
        owns_reservation = reserve.attributes() != attributes;
    }
    if (status < 0)
        return status;
    NativeBuffer storage(state.api, sizeof(ProcessImage));
    auto image = storage.as<ProcessImage>();
    auto prepared =
        image ? identify_process(state.api, *process, *image) : status_unsuccessful;
    if (owns_reservation && prepared >= 0 && !image->related)
        prepared = status_invalid_image;
    if (prepared < 0) {
        if (owns_reservation || state.native_relay || (image && image->related))
            goto failed;
        agent_log(state, "child classification unavailable; left uninstrumented",
                  static_cast<ULONG>(prepared));
    } else if (image->related || state.native_relay) {
        prepared = clone_agent(*process, *thread, *image, state, owns_reservation);
        if (prepared < 0)
            goto failed;
        agent_log(state, image->related ? "injected MSYS child" : "injected native relay",
                  reinterpret_cast<ULONG_PTR>(*process));
    } else {
        agent_log(state, "native child left uninstrumented", reinterpret_cast<ULONG_PTR>(*process));
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
