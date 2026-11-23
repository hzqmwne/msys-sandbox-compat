#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/native_buffer.h"
#include "msys_sandbox_compat/object_security.h"
#include <string.h>
#include <intrin.h>
#include <type_traits>

namespace msys_sandbox_compat {

namespace {
struct PendingHook {
    HookPlan plan;
    BYTE source[hook_source_bytes];
    size_t source_size;
};

bool same_code(const BYTE *left, const BYTE *right, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (left[i] != right[i])
            return false;
    return true;
}

NTSTATUS read_hook_source(const NativeApi &api, HANDLE process, uintptr_t address,
                          PendingHook &pending) {
    pending.source_size = 0;
    if (address > UINTPTR_MAX - hook_source_bytes)
        return status_not_supported;
    while (pending.source_size < hook_source_bytes) {
        const auto at = address + pending.source_size;
        MEMORY_BASIC_INFORMATION info{};
        auto status = api.query_memory(process, reinterpret_cast<void *>(at), 0, &info,
                                       sizeof(info), nullptr);
        if (status < 0 || info.State != MEM_COMMIT ||
            (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
            !(info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            break;
        const auto base = reinterpret_cast<uintptr_t>(info.BaseAddress);
        if (base > at || info.RegionSize <= at - base)
            break;
        size_t available = info.RegionSize - (at - base);
        // A five-byte patch must stay in one protection region. The read may
        // continue across other regions to decode a complete final instruction.
        if (!pending.source_size && available < hook_patch_bytes)
            return status_not_supported;
        if (available > hook_source_bytes - pending.source_size)
            available = hook_source_bytes - pending.source_size;
        SIZE_T transferred = 0;
        status = api.read(process, reinterpret_cast<void *>(at),
                          pending.source + pending.source_size, available, &transferred);
        if (status < 0 || transferred != available)
            break;
        pending.source_size += available;
    }
    return pending.source_size >= hook_patch_bytes ? status_success : status_not_supported;
}

} // namespace

uint32_t selected_hooks(uint32_t modules) {
    uint32_t selected = 0;
    if (modules & bit(Module::propagation))
        selected |= bit(HookId::create_process);
    if (modules & bit(Module::ipc))
        selected |= bit(HookId::directory) | bit(HookId::section) | bit(HookId::mutant) |
                    bit(HookId::symbolic_link) | bit(HookId::named_pipe);
    if (modules & bit(Module::dll_placement))
        selected |= bit(HookId::map_view);
    if (modules & bit(Module::process_dacl))
        selected |= bit(HookId::set_security);
    if (modules & bit(Module::token_dacl))
        selected |= bit(HookId::set_token);
    return selected;
}

NativeApi bind_original_calls(const AgentState &state, uint32_t installed) {
    NativeApi api = state.api;
    visit_hooks(api, [&](HookId id, const char *, auto &entry) {
        const auto &slot = state.hooks[static_cast<size_t>(id)];
        if (slot.target) {
            const auto address = installed & bit(id) ? slot.trampoline : slot.target;
            entry = reinterpret_cast<std::remove_reference_t<decltype(entry)>>(address);
        }
    });
    return api;
}

NTSTATUS replace_entry(const NativeApi &api, HANDLE process, void *entry, const BYTE *code) {
    PVOID region = entry;
    SIZE_T extent = hook_patch_bytes;
    ULONG protection = 0, ignored = 0;
    auto status = api.protect(process, &region, &extent, PAGE_EXECUTE_READWRITE, &protection);
    if (status < 0)
        return status;
    SIZE_T transferred = 0;
    status = api.write(process, entry, code, hook_patch_bytes, &transferred);
    const auto restored = api.protect(process, &region, &extent, protection, &ignored);
    if (status < 0 || restored < 0)
        return status < 0 ? status : restored;
    return transferred == hook_patch_bytes ? status_success : status_unsuccessful;
}

NTSTATUS install_hooks(const NativeApi &api, HANDLE process, const AgentState &state,
                        uint32_t installed, BYTE *loader_entry) {
    // The target is suspended or executing only the initial startup routine.
    // Its caller terminates the new process on partial installation.
    // Keep batch storage off MSYS secondary-thread stacks. Each child's own
    // entry bytes are read again; no predecessor addresses are cloned blindly.
    NativeBuffer storage(api, sizeof(PendingHook) * hook_count);
    auto pending = storage.as<PendingHook>();
    if (!pending)
        return status_unsuccessful;
    for (size_t index = 0; index < hook_count; ++index) {
        if (!(installed & (1u << index)))
            continue;
        const auto &hook = state.hooks[index];
        auto &item = pending[index];
        auto status = read_hook_source(api, process, hook.target, item);
        if (status < 0)
            return status;
        const HookRequest request{hook.target, hook.handler, hook.trampoline, item.source,
                                  item.source_size};
        auto error = plan_inline_hook(request, item.plan);
        if (error != HookPlanError::none) {
            agent_log(state, "hook plan rejected", (index << 8) | static_cast<size_t>(error));
            return status_not_supported;
        }
    }
    // Write all trampolines before exposing any handler to the target process.
    for (size_t index = 0; index < hook_count; ++index) {
        if (!(installed & (1u << index)))
            continue;
        auto status = api.write(process, reinterpret_cast<void *>(state.hooks[index].trampoline),
                                pending[index].plan.trampoline, hook_trampoline_bytes, nullptr);
        if (status < 0)
            return status;
    }
    for (size_t index = 0; index < hook_count; ++index) {
        if (!(installed & (1u << index)))
            continue;
        auto &item = pending[index];
        const auto &hook = state.hooks[index];
        BYTE current[hook_source_bytes]{};
        size_t verify = item.plan.consumed;
        if (verify < hook_patch_bytes)
            verify = hook_patch_bytes;
        SIZE_T transferred = 0;
        auto status =
            api.read(process, reinterpret_cast<void *>(hook.target), current, verify, &transferred);
        if (status < 0 || transferred != verify || !same_code(current, item.source, verify))
            return status < 0 ? status : status_not_supported;
        if (loader_entry && index == static_cast<size_t>(HookId::startup)) {
            status = api.write(process, loader_entry, current, hook_patch_bytes, &transferred);
            if (status < 0 || transferred != hook_patch_bytes)
                return status < 0 ? status : status_unsuccessful;
        }
        status = replace_entry(api, process, reinterpret_cast<void *>(hook.target), item.plan.patch);
        if (status < 0)
            return status;
    }
    return api.flush_code(process, nullptr, 0);
}

NTSTATUS adapt_child_objects(HANDLE process, HANDLE thread, AgentState &state) {
    if (state.plain_context || !state.enabled(Module::process_dacl))
        return status_success;
    // MSYS fork resumes past the cold-start NtSetSecurityObject call. Signal
    // delivery still reopens the target with PROCESS_DUP_HANDLE. Disabling
    // this creation-time adaptation broke signals in PSEC and FullRestricted.
    const auto &api = state.api;
    auto status = adapt_kernel_object(api, process, state);
    return status < 0 ? status : adapt_kernel_object(api, thread, state);
}

static ULONG section_protection(DWORD flags) {
    if (flags & IMAGE_SCN_MEM_EXECUTE)
        return flags & IMAGE_SCN_MEM_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return flags & IMAGE_SCN_MEM_WRITE ? PAGE_READWRITE : PAGE_READONLY;
}

NTSTATUS protect_agent(const NativeApi &api, HANDLE process, const void *image, AgentState &state) {
    const PeView view(image, state.self_size);
    const auto pe = view.headers();
    if (!pe)
        return status_invalid_image;
    const auto sections = view.sections(*pe);
    if (!sections)
        return status_invalid_image;
    for (WORD index = 0; index < pe->FileHeader.NumberOfSections; ++index) {
        PVOID region = reinterpret_cast<void *>(state.self_base + sections[index].VirtualAddress);
        SIZE_T extent = sections[index].Misc.VirtualSize;
        if (!extent)
            continue;
        ULONG previous = 0;
        auto status = api.protect(process, &region, &extent,
                                  section_protection(sections[index].Characteristics), &previous);
        if (status < 0)
            return status;
    }
    return status_success;
}

NTSTATUS stage_startup(const NativeApi &api, HANDLE process, const AgentState &state,
                        AgentState *remote, const ParentStartData &parent) {
    NativeBuffer storage(api, sizeof(ProcessState));
    auto local = storage.as<ProcessState>();
    if (!local)
        return status_unsuccessful;
    auto status = api.write(process, &remote->local, local, sizeof(*local), nullptr);
    if (status < 0)
        return status;
    status = api.write(process, &remote->parent, &parent, sizeof(parent), nullptr);
    if (status < 0)
        return status;
    const auto child_api = bind_original_calls(state, 0);
    status = api.write(process, &remote->api, &child_api, sizeof(child_api), nullptr);
    if (status < 0)
        return status;
    return install_hooks(api, process, state, bit(HookId::startup), remote->local.loader_entry);
}

NTSTATUS clone_agent(HANDLE process, AgentState &source) {
    auto &api = source.api;
    PVOID remote = reinterpret_cast<void *>(source.self_base);
    SIZE_T size = source.self_size;
    auto status = api.allocate(process, &remote, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status < 0 || reinterpret_cast<uintptr_t>(remote) != source.self_base)
        return status < 0 ? status : status_unsuccessful;
    // Preserve the agent's relocated addresses. The child rebuilds its own
    // runtime hooks before Windows initializes its imports.
    status = api.write(process, remote, reinterpret_cast<void *>(source.self_base),
                       source.self_size, nullptr);
    if (status < 0)
        return status;
    status = stage_startup(api, process, source, &source, source.local.image);
    if (status < 0)
        return status;
    return protect_agent(api, process, reinterpret_cast<void *>(source.self_base), source);
}

void agent_log(const AgentState &state, const char *event, ULONG_PTR number) {
    if (!state.trace)
        return;
    char line[160];
    size_t used = 0;
    const char prefix[] = "[agent] ";
    for (char c : prefix)
        if (c)
            line[used++] = c;
    while (*event && used < 110)
        line[used++] = *event++;
    line[used++] = ' ';
    constexpr char digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4)
        line[used++] = digits[(number >> shift) & 15];
    line[used++] = '\n';
    // The handle comes from the current PEB's process parameters, including
    // fork's redirected stderr. Do not retain the parent's handle value.
    auto peb = reinterpret_cast<BYTE *>(__readgsqword(0x60));
    auto parameters = *reinterpret_cast<BYTE **>(peb + 0x20);
    HANDLE error = *reinterpret_cast<HANDLE *>(parameters + 0x30);
    IO_STATUS_BLOCK io{};
    state.api.write_file(error, nullptr, nullptr, nullptr, &io, line, static_cast<ULONG>(used),
                         nullptr, nullptr);
}

} // namespace msys_sandbox_compat
