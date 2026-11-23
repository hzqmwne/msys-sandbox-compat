#include "agent_image.h"
#include "msys_sandbox_compat/pe_view.h"
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace msys_sandbox_compat {
namespace {
void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
} // namespace

AgentImage load_agent_image(const std::filesystem::path &path, uint32_t required_hooks) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    require(input.good(), "open agent DLL");
    const auto bytes = static_cast<std::streamoff>(input.tellg());
    require(bytes > 0, "agent DLL file size");
    std::vector<BYTE> raw(static_cast<size_t>(bytes));
    input.seekg(0);
    require(static_cast<bool>(input.read(reinterpret_cast<char *>(raw.data()), bytes)),
            "read agent DLL");
    return load_agent_image(raw.data(), raw.size(), required_hooks);
}

AgentImage load_agent_image(const BYTE *raw, size_t raw_size, uint32_t required_hooks) {
    const PeView file(raw, raw_size);
    const auto pe = file.headers();
    require(pe && (pe->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
                pe->OptionalHeader.NumberOfRvaAndSizes >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
            "agent must be an AMD64 PE DLL");
    const auto &header = pe->OptionalHeader;
    const auto &directories = header.DataDirectory;
    require(!header.AddressOfEntryPoint && !directories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size &&
                !directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size &&
                !directories[IMAGE_DIRECTORY_ENTRY_TLS].Size,
            "agent DLL must have no entry point, imports or TLS");
    require(header.SizeOfImage && header.SizeOfImage <= max_agent_image_size &&
                header.SizeOfHeaders && header.SizeOfHeaders <= raw_size &&
                header.SizeOfHeaders <= header.SizeOfImage,
            "agent DLL header and image sizes");
    const auto sections = PeView(raw, header.SizeOfHeaders).sections(*pe);
    require(sections && pe->FileHeader.NumberOfSections, "agent DLL section table");

    AgentImage result;
    result.mapped.resize(header.SizeOfImage);
    std::memcpy(result.mapped.data(), raw, header.SizeOfHeaders);
    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; ++i) {
        const auto &section = sections[i];
        const auto rva = section.VirtualAddress;
        const auto offset = section.PointerToRawData;
        const auto size = section.SizeOfRawData;
        require(rva >= header.SizeOfHeaders && rva <= result.mapped.size() &&
                    section.Misc.VirtualSize <= result.mapped.size() - rva &&
                    size <= result.mapped.size() - rva && offset <= raw_size &&
                    size <= raw_size - offset,
                "agent DLL section range");
        if (size)
            std::memcpy(result.mapped.data() + rva, raw + offset, size);
    }

    const PeView image(result.mapped.data(), result.mapped.size());
    const auto abi_rva = image.exported_rva("g_agent_abi");
    const auto abi = abi_rva ? image.at<uint32_t>(abi_rva) : nullptr;
    require(abi && *abi == agent_abi, "agent state version");
    result.state = image.exported_rva("g_agent_state");
    result.thunks = image.exported_rva("g_agent_thunks");
    result.stack_probe = image.exported_rva("g_native_chkstk");
    require(result.state >= header.SizeOfHeaders && image.at<AgentState>(result.state) &&
                result.thunks >= header.SizeOfHeaders &&
                image.at<BYTE>(result.thunks, hook_count * hook_trampoline_bytes) &&
                result.stack_probe >= header.SizeOfHeaders && image.at<uintptr_t>(result.stack_probe),
            "agent DLL data export ranges");

    NativeApi unused{};
    visit_hooks(unused, [&](HookId id, const char *name, const auto &) {
        if (required_hooks & bit(id)) {
            const auto rva = image.exported_rva(name);
            require(rva != 0, "agent DLL missing required hook export");
            result.entries[static_cast<size_t>(id)] = rva;
        }
    });
    auto &startup = result.entries[static_cast<size_t>(HookId::startup)];
    startup = image.exported_rva("start_agent");
    require(startup != 0, "agent DLL missing startup export");
    return result;
}

void AgentImage::relocate(uintptr_t base) {
    const PeView image(mapped.data(), mapped.size());
    const auto &header = image.headers()->OptionalHeader;
    const auto &directory = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!directory.Size)
        return;
    require(directory.VirtualAddress && image.at<BYTE>(directory.VirtualAddress, directory.Size),
            "agent DLL relocation directory range");
    const auto delta = base - header.ImageBase;
    const size_t rva = directory.VirtualAddress;
    const size_t bytes = directory.Size;
    for (size_t used = 0; used < bytes;) {
        const auto block = image.at<IMAGE_BASE_RELOCATION>(rva + used);
        require(block && block->SizeOfBlock >= sizeof(*block) &&
                    block->SizeOfBlock <= bytes - used &&
                    (block->SizeOfBlock - sizeof(*block)) % sizeof(WORD) == 0,
                "agent DLL relocation block");
        const auto count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
        const auto fixups = image.at<WORD>(rva + used + sizeof(*block), count);
        const size_t page = block->VirtualAddress;
        used += block->SizeOfBlock;
        for (size_t i = 0; i < count; ++i) {
            const WORD entry = fixups[i];
            const auto type = entry >> 12;
            if (type == IMAGE_REL_BASED_ABSOLUTE)
                continue;
            const auto target = page + (entry & 0xfff);
            require(type == IMAGE_REL_BASED_DIR64 && target >= header.SizeOfHeaders &&
                        image.at<uint64_t>(target),
                    "agent DLL relocation type or target");
            uint64_t value;
            std::memcpy(&value, mapped.data() + target, sizeof(value));
            value += delta;
            std::memcpy(mapped.data() + target, &value, sizeof(value));
        }
    }
}
} // namespace msys_sandbox_compat
