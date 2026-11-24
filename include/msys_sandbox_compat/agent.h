#pragma once

#include "identify.h"
#include "inline_hook.h"
#include "native_buffer.h"
#include <limits.h>
#include <type_traits>

namespace msys_sandbox_compat {

constexpr size_t object_root_chars = 512;
constexpr uint32_t agent_abi = 7;

enum class Module : uint32_t {
    propagation = 1u << 0,
    heap_window = 1u << 1,
    exe_placement = 1u << 2,
    dll_placement = 1u << 3,
    ipc = 1u << 4,
    process_dacl = 1u << 5,
    token_dacl = 1u << 6
};

constexpr uint32_t bit(Module module) { return static_cast<uint32_t>(module); }
constexpr uint32_t msys_modules = bit(Module::propagation) | bit(Module::heap_window) |
                                  bit(Module::exe_placement) | bit(Module::dll_placement) |
                                  bit(Module::ipc) | bit(Module::process_dacl) |
                                  bit(Module::token_dacl);
constexpr uint32_t acl_modules = bit(Module::ipc) | bit(Module::process_dacl) | bit(Module::token_dacl);

// AMD64 MSYS uses the range below mmap for runtime stacks, cygheap and userheap.
// Keep that address window clear only through kernel process creation.
constexpr uintptr_t msys_heap_base = 0x200000000ULL;
constexpr size_t msys_heap_extent = 0x1000000000ULL - msys_heap_base;

class HeapReservation {
  public:
    HeapReservation(const NativeApi &api, void *attributes);
    void *attributes() const { return attributes_; }

  private:
    HeapReservation(const NativeApi &api, void *attributes, SIZE_T bytes);
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
    create_process,
    set_token,
    set_security,
    startup,
    count
};
constexpr size_t hook_count = static_cast<size_t>(HookId::count);
constexpr uint32_t bit(HookId hook) { return 1u << static_cast<size_t>(hook); }

template <typename Visit> void visit_hooks(NativeApi &api, Visit visit) {
    visit(HookId::directory, "hook_directory", api.create_directory);
    visit(HookId::section, "hook_section", api.create_section);
    visit(HookId::mutant, "hook_mutant", api.create_mutant);
    visit(HookId::symbolic_link, "hook_link", api.create_link);
    visit(HookId::named_pipe, "hook_pipe", api.create_pipe);
    visit(HookId::map_view, "hook_map", api.map_section);
    visit(HookId::create_process, "hook_process", api.create_process);
    visit(HookId::set_token, "hook_set_token", api.set_token);
    visit(HookId::set_security, "hook_set_security", api.set_security);
}

struct HookSlot {
    uintptr_t target;
    uintptr_t handler;
    uintptr_t trampoline;
};

struct ParentStartData {
    uintptr_t image_base;
    wchar_t image_path[image_path_chars];
};

struct ProcessState {
    volatile LONG unwind_registered;
    BYTE loader_entry[hook_patch_bytes];
    PVOID volatile object_security;
    ParentStartData image;
};

struct AgentState {
    uint32_t trace;
    uint32_t native_relay;
    uintptr_t self_base;
    uint32_t self_size;
    NativeApi api;
    wchar_t object_root[object_root_chars];
    uint32_t root_chars;
    HookSlot hooks[hook_count];
    // Process-local fields are reset when cloning into a new suspended child.
    ProcessState local;
    ParentStartData parent;
    uint32_t disabled_modules;
    HANDLE trace_file;

    uint32_t modules() const { return msys_modules & ~disabled_modules; }
    bool enabled(Module module) const { return (modules() & bit(module)) != 0; }
    uint32_t modules_for_image(bool msys) const {
        return msys ? modules() : native_relay ? bit(Module::propagation) : 0;
    }
};

static_assert(sizeof(void *) == 8, "The agent supports AMD64 only");
static_assert(hook_count > 0 && hook_count <= sizeof(uint32_t) * CHAR_BIT);
static_assert(std::is_trivially_copyable_v<AgentState> && std::is_standard_layout_v<AgentState>);
static_assert(std::is_trivially_copyable_v<ParentStartData> &&
              std::is_standard_layout_v<ParentStartData>);

NTSTATUS protect_agent(const NativeApi &api, HANDLE process, const void *image, AgentState &state);
uint32_t selected_hooks(uint32_t modules);
NativeApi bind_original_calls(const AgentState &state, uint32_t installed);
NTSTATUS install_hooks(const NativeApi &api, HANDLE process, const AgentState &state,
                        uint32_t installed, BYTE *loader_entry = nullptr);
NTSTATUS replace_entry(const NativeApi &api, HANDLE process, void *entry, const BYTE *code);
NTSTATUS stage_startup(const NativeApi &api, HANDLE process, const AgentState &state,
                        AgentState *remote, const ParentStartData &parent);
void capture_parent_image(const NativeApi &api, uintptr_t base, ParentStartData &image);
NTSTATUS prepare_exe_layout(AgentState &state, BYTE *peb, CONTEXT &saved, uintptr_t &base,
                            const ImageRecord &image);
NTSTATUS release_heap_reservation(const NativeApi &api, HANDLE process, const AgentState &state);
NTSTATUS clone_agent(HANDLE process, AgentState &source);
void agent_log(const AgentState &state, const char *event, ULONG_PTR number = 0);

} // namespace msys_sandbox_compat
