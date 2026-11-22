#include "msys_sandbox_compat/agent.h"

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

NTSTATUS prepare_exe_layout(const NativeApi &api, HANDLE process, HANDLE thread,
                            const ProcessImage &image) {
    PROCESS_BASIC_INFORMATION basic{};
    auto status = api.query_process(process, ProcessBasicInformation, &basic, sizeof(basic), nullptr);
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

} // namespace msys_sandbox_compat
