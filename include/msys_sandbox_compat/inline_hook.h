#pragma once

#include <stddef.h>
#include <stdint.h>

namespace msys_sandbox_compat {

constexpr size_t hook_patch_bytes = 5;
constexpr size_t hook_source_bytes = 32;
constexpr size_t hook_trampoline_bytes = 64;

// Addresses belong to the target process; bytes belong to the caller. Backends
// must not dereference target-process addresses or depend on loader/CRT state.
struct HookRequest {
    uintptr_t target;
    uintptr_t handler;
    uintptr_t trampoline;
    const unsigned char *source;
    size_t source_size;
};

struct HookPlan {
    unsigned char original[hook_patch_bytes];
    unsigned char patch[hook_patch_bytes];
    unsigned char trampoline[hook_trampoline_bytes];
    uint8_t consumed;
    uint8_t emitted;
};

enum class HookPlanError { none, input, instruction, branch, range, capacity };

// Pure planning boundary. The installer owns remote reads, verification,
// protection, writes, rollback and instruction-cache flush. The entry patch is
// always E9 rel32 to handler; a future Detours backend can replace this
// implementation without changing callers or state.
HookPlanError plan_inline_hook(const HookRequest &request, HookPlan &plan);

} // namespace msys_sandbox_compat
