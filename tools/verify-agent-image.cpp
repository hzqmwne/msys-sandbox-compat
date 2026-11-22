#include "agent_image.h"
#include "msys_sandbox_compat/pe_view.h"
#include <cstdio>
#include <stdexcept>

using namespace msys_sandbox_compat;

int wmain(int argc, wchar_t **argv) try {
    if (argc != 2)
        throw std::runtime_error("expected one agent DLL path");
    auto agent = load_agent_image(argv[1], UINT32_MAX);
    const PeView image(agent.mapped.data(), agent.mapped.size());
    const auto &pe = *image.headers();
    const auto sections = image.sections(pe);
    const auto in_section = [&](uint32_t rva, size_t size, DWORD flags) {
        for (WORD i = 0; i < pe.FileHeader.NumberOfSections; ++i) {
            const auto &section = sections[i];
            if (rva >= section.VirtualAddress && (section.Characteristics & flags) == flags) {
                const auto offset = rva - section.VirtualAddress;
                if (offset <= section.Misc.VirtualSize && size <= section.Misc.VirtualSize - offset)
                    return true;
            }
        }
        return false;
    };
    for (const auto rva : agent.entries)
        if (!in_section(rva, 1, IMAGE_SCN_MEM_EXECUTE))
            throw std::runtime_error("agent handler must be in an executable section");
    if (!in_section(agent.thunks, hook_count * hook_trampoline_bytes, IMAGE_SCN_MEM_EXECUTE) ||
        !in_section(agent.state, sizeof(AgentState), IMAGE_SCN_MEM_WRITE) ||
        !in_section(agent.stack_probe, sizeof(uintptr_t), IMAGE_SCN_MEM_WRITE))
        throw std::runtime_error("agent state, stack probe or trampoline section layout");
    const auto &exception = pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!exception.Size || exception.Size % sizeof(RUNTIME_FUNCTION) ||
        !in_section(exception.VirtualAddress, exception.Size, IMAGE_SCN_MEM_READ))
        throw std::runtime_error("agent unwind directory section layout");

    agent.relocate(pe.OptionalHeader.ImageBase);
    puts("Agent DLL verified");
    return 0;
} catch (const std::exception &error) {
    fprintf(stderr, "Agent DLL verification failed: %s\n", error.what());
    return 1;
}
