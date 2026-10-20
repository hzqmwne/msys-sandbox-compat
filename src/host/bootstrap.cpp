#include "host.h"
#include "msys_compat/injector.h"
#include "msys_compat/pe_view.h"
#include <fstream>
#include <iterator>
#include <type_traits>

namespace msys_compat {
void inject_root(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &state,
                 const std::filesystem::path &agent) {
    std::ifstream input(agent, std::ios::binary);
    check(input.good(), "open agent");
    std::vector<BYTE> raw{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    auto pe = PeView(raw.data(), raw.size()).headers();
    check(pe != nullptr, "agent AMD64 PE");
    check(!pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size &&
              !pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
          "agent must have no imports or TLS");
    std::vector<BYTE> mapped(pe->OptionalHeader.SizeOfImage);
    check(pe->OptionalHeader.SizeOfHeaders <= raw.size(), "agent header size");
    memcpy(mapped.data(), raw.data(), pe->OptionalHeader.SizeOfHeaders);
    auto sections = IMAGE_FIRST_SECTION(pe);
    for (WORD index = 0; index < pe->FileHeader.NumberOfSections; ++index) {
        auto &section = sections[index];
        check(section.PointerToRawData <= raw.size() &&
                  section.SizeOfRawData <= raw.size() - section.PointerToRawData &&
                  section.VirtualAddress <= mapped.size() &&
                  section.SizeOfRawData <= mapped.size() - section.VirtualAddress,
              "bounded agent section");
        memcpy(mapped.data() + section.VirtualAddress, raw.data() + section.PointerToRawData,
               section.SizeOfRawData);
    }
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
    auto delta = state.self_base - pe->OptionalHeader.ImageBase;
    PeView view(mapped.data(), mapped.size());
    const auto &relocations = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    for (size_t used = 0; used < relocations.Size;) {
        auto block = view.at<IMAGE_BASE_RELOCATION>(relocations.VirtualAddress + used);
        check(block && block->SizeOfBlock >= sizeof(*block) &&
                  block->SizeOfBlock <= relocations.Size - used,
              "agent relocation block");
        size_t count = (block->SizeOfBlock - sizeof(*block)) / 2;
        auto entries = view.at<WORD>(relocations.VirtualAddress + used + sizeof(*block), count);
        check(entries != nullptr, "agent relocation entries");
        for (size_t index = 0; index < count; ++index) {
            auto type = entries[index] >> 12;
            if (!type)
                continue;
            check(type == IMAGE_REL_BASED_DIR64, "AMD64 agent relocation type");
            auto address = const_cast<uint64_t *>(
                view.at<uint64_t>(block->VirtualAddress + (entries[index] & 0xfff)));
            check(address != nullptr, "agent relocation target");
            *address += delta;
        }
        used += block->SizeOfBlock;
    }
    auto state_rva = view.exported_rva("g_agent_state");
    auto thunk_rva = view.exported_rva("g_agent_thunks");
    auto probe_rva = view.exported_rva("g_native_chkstk");
    check(state_rva && thunk_rva && probe_rva, "agent data exports");
    auto stack_probe =
        reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "__chkstk"));
    check(stack_probe != 0, "ntdll stack probe");
    memcpy(mapped.data() + probe_rva, &stack_probe, sizeof(stack_probe));
    NativeApi originals = api;
    auto bind = [&](HookId id, const char *name, auto &entry) {
        auto handler = view.exported_rva(name);
        check(handler != 0, "agent handler export");
        auto index = static_cast<size_t>(id);
        auto &hook = state.hooks[index];
        hook = {reinterpret_cast<uintptr_t>(entry), state.self_base + handler,
                state.self_base + thunk_rva + index * 32};
        entry = reinterpret_cast<std::remove_reference_t<decltype(entry)>>(hook.trampoline);
    };
    check_nt(prepare_process(originals, process, thread, image, state), "prepare MSYS root");
    bind(HookId::directory, "hook_directory", api.create_directory);
    bind(HookId::section, "hook_section", api.create_section);
    bind(HookId::mutant, "hook_mutant", api.create_mutant);
    bind(HookId::symbolic_link, "hook_link", api.create_link);
    bind(HookId::named_pipe, "hook_pipe", api.create_pipe);
    bind(HookId::map_view, "hook_map", api.map_section);
    bind(HookId::allocate, "hook_allocate", api.allocate);
    bind(HookId::create_process, "hook_process", api.create_process);
    memcpy(mapped.data() + state_rva, &state, sizeof(state));
    check_nt(originals.write(process, remote, mapped.data(), mapped.size(), nullptr),
             "write agent");
    check_nt(protect_agent(originals, process, mapped.data(), state), "agent section protection");
    check_nt(install_hooks(originals, process, state), "install root inline hooks");
    state.api = originals;
}
} // namespace msys_compat
