#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/native_buffer.h"
#include "msys_sandbox_compat/object_security.h"
#include <string.h>
#include <intrin.h>

namespace msys_sandbox_compat {

namespace {
constexpr ULONG_PTR process_image_name = 0x20005;
constexpr ULONG_PTR process_memory_reserve = 0x20007;

struct CreateAttribute {
    ULONG_PTR type;
    SIZE_T size;
    const void *value;
    SIZE_T *return_size;
};

struct ReserveRange {
    void *base;
    SIZE_T size;
};

struct CreateInput {
    SIZE_T bytes;
    CreateAttribute entries[65]; // Room for 64 caller attributes and the appended range.
    wchar_t path[image_path_chars];
    ReserveRange range;
};

struct PendingHook {
    HookPlan plan;
    BYTE source[hook_source_bytes];
    size_t source_size;
    bool selected;
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

HeapReservation::HeapReservation(const NativeApi &api, void *attributes)
    : storage_(api, attributes ? sizeof(CreateInput) : 0), attributes_(attributes) {
    auto input = storage_.as<CreateInput>();
    if (!input)
        return;
    SIZE_T bytes = 0, read = 0;
    if (api.read(current_process(), attributes, &bytes, sizeof(bytes), &read) < 0 ||
        read != sizeof(bytes) || bytes < sizeof(bytes) + sizeof(CreateAttribute) ||
        bytes > offsetof(CreateInput, path) - sizeof(CreateAttribute) ||
        (bytes - sizeof(bytes)) % sizeof(CreateAttribute))
        return;
    if (api.read(current_process(), attributes, input, bytes, &read) < 0 || read != bytes ||
        input->bytes != bytes)
        return;
    const auto count = (bytes - sizeof(bytes)) / sizeof(CreateAttribute);
    const CreateAttribute *image = nullptr;
    for (size_t index = 0; index < count; ++index) {
        const auto &entry = input->entries[index];
        if (entry.type == process_memory_reserve)
            return; // Preserve a reservation already supplied by the caller.
        if (entry.type == process_image_name)
            image = &entry;
    }
    if (!image || !image->size || image->size >= sizeof(input->path) ||
        image->size % sizeof(wchar_t) ||
        api.read(current_process(), image->value, input->path, image->size, &read) < 0 ||
        read != image->size ||
        !imports_msys(api, input->path, image->size / sizeof(wchar_t)))
        return;

    input->range = {reinterpret_cast<void *>(msys_heap_base), msys_heap_extent};
    input->entries[count] = {process_memory_reserve, sizeof(input->range), &input->range, nullptr};
    input->bytes += sizeof(CreateAttribute);
    attributes_ = input;
}

NTSTATUS install_hooks(const NativeApi &api, HANDLE process, AgentState &state, bool msys) {
    // The new image is still writable and its initial thread is suspended.
    // On failure the caller terminates this new process; partial installation
    // is never resumed, so there is no cross-entry rollback transaction.
    // Keep batch storage off MSYS secondary-thread stacks. Each child's own
    // entry bytes are read again; no predecessor addresses are cloned blindly.
    NativeBuffer storage(api, sizeof(PendingHook) * hook_count);
    auto pending = storage.as<PendingHook>();
    if (!pending)
        return status_unsuccessful;
    for (size_t index = 0; index < hook_count; ++index) {
        const auto &hook = state.hooks[index];
        auto &item = pending[index];
        item = {};
        item.selected = msys || index == static_cast<size_t>(HookId::create_process);
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
    // Relays also need unpatched original entries for classification/preparation.
    // Write all trampolines before exposing any handler to the target process.
    for (size_t index = 0; index < hook_count; ++index) {
        auto status = api.write(process, reinterpret_cast<void *>(state.hooks[index].trampoline),
                                pending[index].plan.trampoline, hook_trampoline_bytes, nullptr);
        if (status < 0)
            return status;
    }
    for (size_t index = 0; index < hook_count; ++index) {
        auto &item = pending[index];
        if (!item.selected)
            continue;
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
        PVOID region = reinterpret_cast<void *>(hook.target);
        SIZE_T extent = hook_patch_bytes;
        ULONG protection = 0, ignored = 0;
        status = api.protect(process, &region, &extent, PAGE_EXECUTE_READWRITE, &protection);
        if (status < 0)
            return status;
        transferred = 0;
        status = api.write(process, reinterpret_cast<void *>(hook.target), item.plan.patch,
                           hook_patch_bytes, &transferred);
        const auto restored = api.protect(process, &region, &extent, protection, &ignored);
        if (status < 0 || transferred != hook_patch_bytes || restored < 0)
            return status < 0 ? status : restored < 0 ? restored : status_unsuccessful;
    }
    return api.flush_code(process, nullptr, 0);
}

NTSTATUS prepare_process(const NativeApi &api, HANDLE process, HANDLE thread,
                         const ProcessImage &image, AgentState &state) {
    // Set only this positively identified child's object ACLs.
    auto status = adapt_kernel_object(api, process, state);
    if (status < 0)
        return status;
    status = adapt_kernel_object(api, thread, state);
    if (status < 0)
        return status;

    PROCESS_BASIC_INFORMATION basic{};
    status = api.query_process(process, ProcessBasicInformation, &basic, sizeof(basic), nullptr);
    if (status < 0)
        return status;
    uintptr_t original = 0;
    auto peb_image = reinterpret_cast<BYTE *>(basic.PebBaseAddress) + 0x10;
    status = api.read(process, peb_image, &original, sizeof(original), nullptr);
    if (status < 0 || original == image.record.preferred_base)
        return status;

    UNICODE_STRING name{};
    name.Buffer = const_cast<PWSTR>(image.path);
    size_t path_chars = 0;
    while (image.path[path_chars])
        ++path_chars;
    name.Length = static_cast<USHORT>(path_chars * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io{};
    HANDLE file = nullptr;
    status = api.open_file(&file, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &attributes, &io,
                           FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (status < 0)
        return status;
    HANDLE section = nullptr;
    status = api.create_section(&section, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY,
                                SEC_IMAGE, file);
    api.close(file);
    if (status < 0)
        return status;
    PVOID address = reinterpret_cast<void *>(image.record.preferred_base);
    SIZE_T extent = 0;
    status =
        api.map_section(section, process, &address, 0, 0, nullptr, &extent, 2, 0, PAGE_READONLY);
    api.close(section);
    if (status < 0 || address != reinterpret_cast<void *>(image.record.preferred_base))
        return status < 0 ? status : status_unsuccessful;
    // A CONTEXT is over 1 KiB on AMD64. This function also runs during fork
    // on MSYS-managed secondary-thread stacks; keep that storage off-stack.
    NativeBuffer context_storage(api, sizeof(CONTEXT));
    auto context = context_storage.as<CONTEXT>();
    if (!context)
        return status_unsuccessful;
    context->ContextFlags = CONTEXT_FULL;
    status = api.get_context(thread, context);
    if (status < 0)
        return status;
    if (context->Rcx >= original && context->Rcx < original + image.record.image_size)
        context->Rcx += image.record.preferred_base - original;
    if (context->Rip >= original && context->Rip < original + image.record.image_size)
        context->Rip += image.record.preferred_base - original;
    status = api.write(process, peb_image, &image.record.preferred_base,
                       sizeof(image.record.preferred_base), nullptr);
    if (status < 0)
        return status;
    // The original randomized SEC_IMAGE view remains mapped: kernel thread
    // creation still uses its metadata even after PEB.ImageBase is replaced.
    return api.set_context(thread, context);
}

static ULONG section_protection(DWORD flags) {
    if (flags & IMAGE_SCN_MEM_EXECUTE)
        return flags & IMAGE_SCN_MEM_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return flags & IMAGE_SCN_MEM_WRITE ? PAGE_READWRITE : PAGE_READONLY;
}

NTSTATUS protect_agent(const NativeApi &api, HANDLE process, const void *image, AgentState &state) {
    auto pe = PeView(image, state.self_size).headers();
    if (!pe)
        return status_invalid_image;
    auto sections = IMAGE_FIRST_SECTION(pe);
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

NTSTATUS release_heap_reservation(const NativeApi &api, HANDLE process, const AgentState &state) {
    PVOID base = reinterpret_cast<void *>(msys_heap_base);
    MEMORY_BASIC_INFORMATION info{};
    auto status = api.query_memory(process, base, 0, &info, sizeof(info), nullptr);
    if (status < 0 || info.BaseAddress != base || info.AllocationBase != base ||
        info.State != MEM_RESERVE || info.RegionSize != msys_heap_extent)
        return status < 0 ? status : status_unsuccessful;
    SIZE_T size = 0;
    status = api.free(process, &base, &size, MEM_RELEASE);
    if (status >= 0)
        agent_log(state, "released MSYS heap window", msys_heap_base);
    return status;
}

NTSTATUS clone_agent(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &source,
                     bool owns_reservation) {
    auto &api = source.api;
    auto status = status_success;
    if (source.native_relay) {
        status = check_child_context(api, process, source);
        if (status < 0)
            return status;
    }
    if (image.related) {
        status = prepare_process(api, process, thread, image, source);
        if (status < 0)
            return status;
    }
    PVOID remote = reinterpret_cast<void *>(source.self_base);
    SIZE_T size = source.self_size;
    status = api.allocate(process, &remote, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status < 0 || reinterpret_cast<uintptr_t>(remote) != source.self_base)
        return status < 0 ? status : status_unsuccessful;
    // All agent internal addresses and trampoline addresses are identical in
    // descendants. Each child's entry bytes are rebuilt by install_hooks.
    status = api.write(process, remote, reinterpret_cast<void *>(source.self_base),
                       source.self_size, nullptr);
    if (status < 0)
        return status;
    ProcessState local{};
    status = api.write(process, &source.local, &local, sizeof(local), nullptr);
    if (status < 0)
        return status;
    status = install_hooks(api, process, source, image.related);
    if (status < 0)
        return status;
    status = protect_agent(api, process, reinterpret_cast<void *>(source.self_base), source);
    return status >= 0 && owns_reservation ? release_heap_reservation(api, process, source) : status;
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
