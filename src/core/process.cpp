#include "msys_compat/agent.h"
#include "msys_compat/pe_view.h"
#include "msys_compat/native_buffer.h"
#include <string.h>
#include <intrin.h>

namespace msys_compat {

// The only supported entry format is the AMD64 ntdll syscall prefix consisting
// of two whole instructions: mov r10,rcx; mov eax,imm32. Refuse other builds or
// an existing hook instead of guessing instruction lengths or overwriting it.
NTSTATUS install_hooks(const NativeApi &api, HANDLE process, AgentState &state, bool msys) {
    // The new image is still writable and its initial thread is suspended.
    // Build the contiguous thunk table once, before final section protection.
    BYTE trampolines[hook_count][32]{};
    for (size_t index = 0; index < hook_count; ++index) {
        const auto &hook = state.hooks[index];
        BYTE original[8];
        auto status = api.read(process, reinterpret_cast<void *>(hook.target), original,
                               sizeof(original), nullptr);
        if (status < 0)
            return status;
        if (original[0] != 0x4c || original[1] != 0x8b || original[2] != 0xd1 ||
            original[3] != 0xb8)
            return status_not_supported;
        auto delta = static_cast<int64_t>(hook.handler) - static_cast<int64_t>(hook.target + 5);
        if (delta < INT32_MIN || delta > INT32_MAX)
            return status_not_supported;

        auto trampoline = trampolines[index];
        memcpy(trampoline, original, 8);
        trampoline[8] = 0xff;
        trampoline[9] = 0x25;
        auto tail = hook.target + 8;
        memcpy(trampoline + 14, &tail, sizeof(tail));
    }
    auto status = api.write(process, reinterpret_cast<void *>(state.hooks[0].trampoline),
                            trampolines, sizeof(trampolines), nullptr);
    if (status < 0)
        return status;
    for (const auto &hook : state.hooks) {
        // Relays need original trampolines for classification/preparation,
        // but only process creation is intercepted in a native image.
        if (!msys && &hook != &state.hooks[static_cast<size_t>(HookId::create_process)])
            continue;
        BYTE patch[8] = {0xe9, 0, 0, 0, 0, 0x90, 0x90, 0x90};
        auto relative = static_cast<int32_t>(hook.handler - (hook.target + 5));
        memcpy(patch + 1, &relative, sizeof(relative));
        PVOID region = reinterpret_cast<void *>(hook.target);
        SIZE_T extent = sizeof(patch);
        ULONG previous = 0, ignored = 0;
        status = api.protect(process, &region, &extent, PAGE_EXECUTE_READWRITE, &previous);
        if (status < 0)
            return status;
        status = api.write(process, reinterpret_cast<void *>(hook.target), patch, sizeof(patch),
                           nullptr);
        api.protect(process, &region, &extent, previous, &ignored);
        if (status < 0)
            return status;
    }
    return api.flush_code(process, nullptr, 0);
}

NTSTATUS prepare_process(const NativeApi &api, HANDLE process, HANDLE thread,
                         const ProcessImage &image, AgentState &state) {
    // Set only this positively identified child's object ACLs. In particular,
    // do not replace NtCreateUserProcess's attributes for every native child.
    auto status = api.set_security(process, DACL_SECURITY_INFORMATION, state.descriptor);
    if (status < 0)
        return status;
    status = api.set_security(thread, DACL_SECURITY_INFORMATION, state.descriptor);
    if (status < 0)
        return status;

    PVOID arena = reinterpret_cast<void *>(relocated_cygheap);
    SIZE_T extent = cygheap_extent;
    status = api.allocate(process, &arena, 0, &extent, MEM_RESERVE, PAGE_NOACCESS);
    if (status < 0 || arena != reinterpret_cast<void *>(relocated_cygheap))
        return status < 0 ? status : status_unsuccessful;

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
    extent = 0;
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

NTSTATUS clone_agent(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &source) {
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
    // descendants. ntdll's address is separately verified by install_hooks.
    status = api.write(process, remote, reinterpret_cast<void *>(source.self_base),
                       source.self_size, nullptr);
    if (status < 0)
        return status;
    size_t directory_chars = 0;
    for (size_t i = 0; image.path[i]; ++i)
        if (image.path[i] == L'\\')
            directory_chars = i + 1;
    status =
        api.write(process, source.application_directory, image.path, directory_chars * 2, nullptr);
    if (status < 0)
        return status;
    const wchar_t terminator = 0;
    status = api.write(process, source.application_directory + directory_chars, &terminator,
                       sizeof(terminator), nullptr);
    if (status < 0)
        return status;
    ProcessState local{};
    status = api.write(process, &source.local, &local, sizeof(local), nullptr);
    if (status < 0)
        return status;
    status = install_hooks(api, process, source, image.related);
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

} // namespace msys_compat
