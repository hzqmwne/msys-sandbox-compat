#include "host.h"
#include "agent_image.h"
#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/pe_view.h"
#include <psapi.h>

namespace msys_sandbox_compat {
namespace {
struct RootCreation {
    const AgentState &state;
    bool &reserved;
};

thread_local RootCreation *root_creation;
CreateUserProcess original_root_create;

NTSTATUS NTAPI reserve_root_heaps(PHANDLE process, PHANDLE thread, ACCESS_MASK process_access,
                                    ACCESS_MASK thread_access, POBJECT_ATTRIBUTES process_attrs,
                                    POBJECT_ATTRIBUTES thread_attrs, ULONG process_flags,
                                    ULONG thread_flags, PRTL_USER_PROCESS_PARAMETERS parameters,
                                    void *create_info, void *attributes) {
    const auto root = root_creation;
    if (!root)
        return original_root_create(process, thread, process_access, thread_access, process_attrs,
                                    thread_attrs, process_flags, thread_flags, parameters,
                                    create_info, attributes);
    agent_log(root->state, "root heap preflight");
    HeapReservation reserve(root->state.api, attributes);
    auto status = original_root_create(process, thread, process_access, thread_access, process_attrs,
                                       thread_attrs, process_flags, thread_flags, parameters,
                                       create_info, reserve.attributes());
    root->reserved = status >= 0 && reserve.attributes() != attributes;
    return status;
}

CreateUserProcess *root_create_slot() {
    const auto module = GetModuleHandleW(L"kernelbase.dll");
    MODULEINFO info{};
    if (!module || !K32GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info)))
        return nullptr;
    PeView view(module, info.SizeOfImage);
    const auto pe = view.headers();
    if (!pe)
        return nullptr;
    const auto &directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const auto count = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const auto imports = view.at<IMAGE_IMPORT_DESCRIPTOR>(directory.VirtualAddress, count);
    for (size_t index = 0; imports && index < count && imports[index].Name; ++index) {
        const auto &entry = imports[index];
        const auto module_name = view.string_at(entry.Name);
        if (!module_name || !ascii_equal(module_name, "ntdll.dll") || !entry.OriginalFirstThunk)
            continue;
        for (size_t offset = 0;; offset += sizeof(IMAGE_THUNK_DATA64)) {
            const auto name = view.at<IMAGE_THUNK_DATA64>(entry.OriginalFirstThunk + offset);
            const auto slot = view.at<CreateUserProcess>(entry.FirstThunk + offset);
            if (!name || !slot || !name->u1.AddressOfData)
                break;
            if (IMAGE_SNAP_BY_ORDINAL64(name->u1.Ordinal))
                continue;
            const auto name_text =
                view.string_at(name->u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name));
            if (name_text && ascii_equal(name_text, "NtCreateUserProcess"))
                return const_cast<CreateUserProcess *>(slot);
        }
    }
    return nullptr;
}
} // namespace

BOOL create_root(PCWSTR executable, PWSTR command, STARTUPINFOEXW &startup, bool conpty,
                 bool inherit_handles,
                 const AgentState *state, PROCESS_INFORMATION &child, bool &reserved) {
    // Keep Win32 in charge of console attachment, handle inheritance and the
    // other creation attributes. The inherited relay already handles this call.
    const auto create = [&] {
        return CreateProcessW(executable, command, nullptr, nullptr, inherit_handles,
                              CREATE_SUSPENDED | (conpty ? EXTENDED_STARTUPINFO_PRESENT : 0),
                              nullptr, nullptr, &startup.StartupInfo, &child);
    };
    auto slot = state && !conpty && state->enabled(Module::heap_window) ? root_create_slot()
                                                                        : nullptr;
    DWORD protection = 0;
    if (!slot || !VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &protection))
        return create();

    original_root_create = *slot;
    auto entry = reinterpret_cast<PVOID volatile *>(slot);
    RootCreation root{*state, reserved};
    root_creation = &root;
    InterlockedExchangePointer(entry, reinterpret_cast<PVOID>(reserve_root_heaps));
    const auto created = create();
    const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
    InterlockedExchangePointer(entry, reinterpret_cast<PVOID>(original_root_create));
    root_creation = nullptr;
    DWORD ignored = 0;
    if (!VirtualProtect(slot, sizeof(*slot), protection, &ignored)) {
        const auto error = GetLastError();
        if (created) {
            ::TerminateProcess(child.hProcess, 1);
            CloseHandle(child.hThread);
            CloseHandle(child.hProcess);
        }
        SetLastError(error);
        return FALSE;
    }
    SetLastError(create_error);
    return created;
}

AgentState *inherited_agent() {
    // An explicit launcher inside an opted-in tree already has the relay.
    // Its CreateProcess call prepares the child; do not inject it a second time.
    auto entry = reinterpret_cast<const BYTE *>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateUserProcess"));
    if (!entry || entry[0] != 0xe9)
        return nullptr;
    LONG offset = 0;
    memcpy(&offset, entry + 1, sizeof(offset));
    auto handler = entry + 5 + offset;
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(handler, &region, sizeof(region)))
        return nullptr;
    auto base = static_cast<const BYTE *>(region.AllocationBase);
    if (!VirtualQuery(base, &region, sizeof(region)) || region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return nullptr;
    auto pe = PeView(base, region.RegionSize).headers();
    if (!pe || !pe->OptionalHeader.SizeOfImage ||
        pe->OptionalHeader.SizeOfImage > max_agent_image_size)
        return nullptr;
    size_t size = pe->OptionalHeader.SizeOfImage;
    for (size_t at = 0; at < size;) {
        if (!VirtualQuery(base + at, &region, sizeof(region)) || region.AllocationBase != base ||
            region.State != MEM_COMMIT || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return nullptr;
        at = static_cast<const BYTE *>(region.BaseAddress) + region.RegionSize - base;
    }
    PeView view(base, size);
    auto state_rva = view.exported_rva("g_agent_state");
    auto handler_rva = view.exported_rva("hook_process");
    if (!state_rva || !handler_rva || base + handler_rva != handler)
        return nullptr;
    const auto abi_rva = view.exported_rva("g_agent_abi");
    const auto abi = abi_rva ? view.at<uint32_t>(abi_rva) : nullptr;
    check_nt(abi && *abi == agent_abi ? status_success : status_not_supported,
             "inherited relay agent state version");
    auto state = view.at<AgentState>(state_rva);
    if (!state || !state->native_relay || state->self_base != reinterpret_cast<uintptr_t>(base) ||
        state->self_size != size)
        return nullptr;
    auto &slot = state->hooks[static_cast<size_t>(HookId::create_process)];
    return slot.target == reinterpret_cast<uintptr_t>(entry) &&
                   slot.handler == reinterpret_cast<uintptr_t>(handler) &&
                   reinterpret_cast<uintptr_t>(state->api.create_process) == slot.trampoline
               ? const_cast<AgentState *>(state)
               : nullptr;
}

void inject_root(HANDLE process, uint32_t installed, const AgentState &host_state,
                 const std::filesystem::path &agent) {
    auto payload = std::make_unique<AgentState>(host_state);
    auto &state = *payload;
    const auto possible = state.enabled(Module::propagation)
                              ? selected_hooks(state.effective_modules(true))
                              : installed;
    auto image = load_agent_image(agent, possible);
    auto &mapped = image.mapped;
    auto &api = state.api;
    auto native = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"ntdll.dll"));
    PVOID remote = nullptr;
    // A nearby image permits rel32 jumps without touching adjacent syscalls.
    for (uintptr_t distance = 0x1000000; distance < 0x70000000; distance += 0x10000) {
        remote = reinterpret_cast<void *>((native - distance) & ~uintptr_t(0xffff));
        SIZE_T size = mapped.size();
        if (api.allocate(process, &remote, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0)
            break;
        remote = nullptr;
    }
    check(remote != nullptr, "allocate agent near ntdll");
    state.self_base = reinterpret_cast<uintptr_t>(remote);
    state.self_size = static_cast<uint32_t>(mapped.size());
    image.relocate(state.self_base);
    auto stack_probe =
        reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "__chkstk"));
    check(stack_probe != 0, "ntdll stack probe");
    memcpy(mapped.data() + image.stack_probe, &stack_probe, sizeof(stack_probe));
    visit_hooks(api, [&](HookId id, const char *, auto &entry) {
        const auto index = static_cast<size_t>(id);
        if (const auto handler = image.entries[index])
            state.hooks[index] = {reinterpret_cast<uintptr_t>(entry), state.self_base + handler,
                                  state.self_base + image.thunks + index * hook_trampoline_bytes};
    });
    const NativeApi &originals = host_state.api;
    const auto startup_entry = reinterpret_cast<uintptr_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrInitializeThunk"));
    check(startup_entry != 0, "loader startup entry");
    const auto startup = static_cast<size_t>(HookId::startup);
    state.hooks[startup] = {startup_entry, state.self_base + image.entries[startup],
                           state.self_base + image.thunks + startup * hook_trampoline_bytes};
    memcpy(mapped.data() + image.state, &state, sizeof(state));
    check_nt(originals.write(process, remote, mapped.data(), mapped.size(), nullptr),
             "write agent");
    auto remote_state = reinterpret_cast<AgentState *>(state.self_base + image.state);
    // A standalone launcher starts a new image. Only a live MSYS parent can
    // supply the image data used by a subsequent fork.
    check_nt(stage_startup(originals, process, state, remote_state, {}),
             "stage root initialization");
    check_nt(protect_agent(originals, process, mapped.data(), state), "agent section protection");
}
} // namespace msys_sandbox_compat
