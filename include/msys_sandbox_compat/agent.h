#pragma once

#include "identify.h"
#include "inline_hook.h"
#include "native_buffer.h"

namespace msys_sandbox_compat {

constexpr size_t object_root_chars = 512;

constexpr uintptr_t original_cygheap = 0x800000000ULL;
constexpr size_t cygheap_extent = 0x200000000ULL;
constexpr uintptr_t original_userheap = 0xa00000000ULL;
constexpr uintptr_t relocated_userheap = 0x80400000000ULL;

class CygheapReservation {
  public:
    CygheapReservation(const NativeApi &api, const RuntimePaths &runtime, void *attributes);
    void *attributes() const { return attributes_; }

  private:
    NativeBuffer storage_;
    void *attributes_;
};

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
    volatile LONG policy_lock;
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
    uint32_t root_chars;
    unsigned char user_sid[SECURITY_MAX_SID_SIZE];
    uint32_t user_sid_bytes;
    unsigned char compat_sid[SECURITY_MAX_SID_SIZE];
    uint32_t compat_sid_bytes;
    // Last successfully observed policy; native relays reject unobserved edits.
    unsigned char token_default_dacl[8192];
    uint32_t token_default_dacl_bytes;
    uint32_t object_policy_valid;
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
