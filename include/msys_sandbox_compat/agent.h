#pragma once

#include "identify.h"

namespace msys_sandbox_compat {

constexpr size_t object_root_chars = 512;
constexpr size_t descriptor_bytes = 1024;

constexpr uintptr_t original_cygheap = 0x800000000ULL;
constexpr uintptr_t relocated_cygheap = 0x80000000000ULL;
constexpr size_t cygheap_extent = 0x200000000ULL;
constexpr uintptr_t original_userheap = 0xa00000000ULL;
constexpr uintptr_t relocated_userheap = relocated_cygheap + 0x400000000ULL;

enum class HookId : size_t {
    directory,
    section,
    mutant,
    symbolic_link,
    named_pipe,
    map_view,
    allocate,
    create_process,
    set_token,
    count
};
constexpr size_t hook_count = static_cast<size_t>(HookId::count);

struct HookSlot {
    uintptr_t target;
    uintptr_t handler;
    uintptr_t trampoline;
};

struct ProcessState {
    volatile LONG runtime_loaded;
    volatile LONG unwind_registered;
};

struct AgentState {
    uint32_t trace;
    uint32_t native_relay;
    uintptr_t self_base;
    uint32_t self_size;
    NativeApi api;
    RuntimePaths runtime;
    wchar_t application_directory[image_path_chars];
    wchar_t object_root[object_root_chars];
    unsigned char descriptor[descriptor_bytes];
    uint32_t root_chars;
    // Preserve the sandbox's initial default object ACL across MSYS init.
    unsigned char token_default_dacl[2048];
    uint32_t token_default_dacl_bytes;
    HookSlot hooks[hook_count];
    // Process-local fields are reset when cloning into a new suspended child.
    ProcessState local;
};

static_assert(sizeof(void *) == 8, "The agent supports AMD64 only");

NTSTATUS protect_agent(const NativeApi &api, HANDLE process, const void *image, AgentState &state);
NTSTATUS install_hooks(const NativeApi &api, HANDLE process, AgentState &state, bool msys);
NTSTATUS check_child_context(const NativeApi &api, HANDLE process, const AgentState &state);
NTSTATUS check_object_policy(const NativeApi &api, HANDLE token, const AgentState &state);
NTSTATUS prepare_process(const NativeApi &api, HANDLE process, HANDLE thread,
                         const ProcessImage &image, AgentState &state);
NTSTATUS clone_agent(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &source);
void agent_log(const AgentState &state, const char *event, ULONG_PTR number = 0);

} // namespace msys_sandbox_compat
