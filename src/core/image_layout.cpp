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

constexpr size_t reservation_tail =
    sizeof(CreateAttribute) + sizeof(ReserveRange) + image_path_chars * sizeof(wchar_t);

SIZE_T create_attribute_bytes(const NativeApi &api, const void *attributes) {
    SIZE_T bytes = 0, received = 0;
    if (!attributes ||
        api.read(current_process(), attributes, &bytes, sizeof(bytes), &received) < 0 ||
        received != sizeof(bytes) || bytes < sizeof(bytes) + sizeof(CreateAttribute) ||
        (bytes - sizeof(bytes)) % sizeof(CreateAttribute) || bytes > SIZE_MAX - reservation_tail)
        return 0;
    return bytes;
}
} // namespace

HeapReservation::HeapReservation(const NativeApi &api, void *attributes)
    : HeapReservation(api, attributes, create_attribute_bytes(api, attributes)) {}

HeapReservation::HeapReservation(const NativeApi &api, void *attributes, SIZE_T bytes)
    : storage_(api, bytes ? bytes + reservation_tail : 0), attributes_(attributes) {
    auto input = storage_.as<BYTE>();
    if (!input)
        return;
    auto total = reinterpret_cast<SIZE_T *>(input);
    SIZE_T read = 0;
    if (api.read(current_process(), attributes, input, bytes, &read) < 0 || read != bytes ||
        *total != bytes)
        return;
    const auto count = (bytes - sizeof(bytes)) / sizeof(CreateAttribute);
    auto entries = reinterpret_cast<CreateAttribute *>(input + sizeof(bytes));
    const CreateAttribute *image = nullptr;
    for (size_t index = 0; index < count; ++index) {
        const auto &entry = entries[index];
        if (entry.type == process_memory_reserve)
            return; // Preserve a reservation already supplied by the caller.
        if (entry.type == process_image_name)
            image = &entry;
    }
    auto range = reinterpret_cast<ReserveRange *>(entries + count + 1);
    auto path = reinterpret_cast<wchar_t *>(range + 1);
    if (!image || !image->size || image->size >= image_path_chars * sizeof(wchar_t) ||
        image->size % sizeof(wchar_t) ||
        api.read(current_process(), image->value, path, image->size, &read) < 0 ||
        read != image->size ||
        !imports_msys(api, path, image->size / sizeof(wchar_t)))
        return;

    *range = {reinterpret_cast<void *>(msys_heap_base), msys_heap_extent};
    entries[count] = {process_memory_reserve, sizeof(*range), range, nullptr};
    *total += sizeof(CreateAttribute);
    attributes_ = input;
}

void capture_parent_image(const NativeApi &api, uintptr_t base, ParentStartData &image) {
    image.image_base = base;
    image.image_path[0] = 0;
    constexpr auto capacity = sizeof(UNICODE_STRING) + sizeof(image.image_path);
    NativeBuffer storage(api, capacity);
    auto name = storage.as<UNICODE_STRING>();
    if (!name)
        return;
    ULONG bytes = 0;
    const auto status = api.query_process(current_process(), static_cast<PROCESSINFOCLASS>(27),
                                          name, capacity, &bytes);
    const auto start = reinterpret_cast<uintptr_t>(name);
    const auto text = reinterpret_cast<uintptr_t>(name->Buffer);
    if (status >= 0 && text >= start + sizeof(*name) && text - start < capacity &&
        !(name->Length % sizeof(wchar_t)) && name->Length < sizeof(image.image_path) &&
        name->Length <= capacity - (text - start)) {
        memcpy(image.image_path, name->Buffer, name->Length);
        image.image_path[name->Length / sizeof(wchar_t)] = 0;
    }
}

namespace {
bool is_runtime_fork(const NativeApi &api, const BYTE *peb) {
    // AMD64 RTL_USER_PROCESS_PARAMETERS stores STARTUPINFO's reserved payload
    // in RuntimeData. Read only the shared child_info prefix.
    struct RuntimeChild {
        DWORD startup_count;
        DWORD bytes;
        DWORD intro;
        DWORD magic;
        WORD type;
    };
    constexpr size_t parameters_offset = 0x20;
    constexpr size_t flags_offset = 0x08;
    constexpr size_t runtime_data_offset = 0xe0;
    constexpr ULONG normalized = 1;
    constexpr DWORD runtime_intro = 0xaf00fa64;
    constexpr WORD fork_type = 3;
    uintptr_t parameters = 0;
    memcpy(&parameters, peb + parameters_offset, sizeof(parameters));
    if (!parameters)
        return false;
    ULONG flags = 0;
    UNICODE_STRING data{};
    const auto process = current_process();
    if (api.read(process, reinterpret_cast<void *>(parameters + flags_offset), &flags,
                 sizeof(flags), nullptr) < 0 ||
        api.read(process, reinterpret_cast<void *>(parameters + runtime_data_offset), &data,
                 sizeof(data), nullptr) < 0 ||
        !data.Buffer || data.Length < sizeof(RuntimeChild) || data.Length > data.MaximumLength)
        return false;
    auto buffer = reinterpret_cast<uintptr_t>(data.Buffer);
    if (!(flags & normalized)) {
        if (buffer > UINTPTR_MAX - parameters)
            return false;
        buffer += parameters;
    }
    RuntimeChild runtime{};
    SIZE_T received = 0;
    return api.read(process, reinterpret_cast<void *>(buffer), &runtime, sizeof(runtime),
                    &received) >= 0 && received == sizeof(runtime) &&
           !runtime.startup_count && runtime.bytes == data.Length && runtime.intro == runtime_intro &&
           runtime.magic && runtime.type == fork_type;
}
} // namespace

NTSTATUS prepare_fork_exe(AgentState &state, BYTE *peb, CONTEXT &saved, uintptr_t &base,
                          const ImageRecord &image) {
    auto &api = state.api;
    const auto &parent = state.parent;
    if (base == parent.image_base || !is_runtime_fork(api, peb))
        return status_success;
    if (!parent.image_base || !parent.image_path[0] || image.entry_rva >= image.image_size ||
        (saved.ContextFlags & CONTEXT_INTEGER) != CONTEXT_INTEGER ||
        saved.Rcx != base + image.entry_rva)
        return status_invalid_image;

    size_t chars = 0;
    while (chars < image_path_chars && parent.image_path[chars])
        ++chars;
    if (chars == image_path_chars)
        return status_invalid_image;
    const auto bytes = static_cast<USHORT>(chars * sizeof(wchar_t));
    UNICODE_STRING name{bytes, bytes, const_cast<PWSTR>(parent.image_path)};
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io{};
    HANDLE file = nullptr;
    auto status = api.open_file(&file, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &attributes,
                                &io, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (status < 0)
        return status;
    HANDLE section = nullptr;
    status = api.create_section(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, nullptr, nullptr,
                                PAGE_READONLY, SEC_IMAGE, file);
    api.close(file);
    if (status < 0)
        return status;
    auto address = reinterpret_cast<void *>(parent.image_base);
    SIZE_T extent = 0;
    const auto process = current_process();
    status = api.map_section(section, process, &address, 0, 0, nullptr, &extent, 2, 0, PAGE_READONLY);
    api.close(section);
    if (status < 0 || address != reinterpret_cast<void *>(parent.image_base))
        return status < 0 ? status : status_unsuccessful;

    ImageRecord mapped{};
    bool related = false;
    status = identify_executable(api, process, address, mapped, related);
    if (status < 0 || !related || mapped.image_size != image.image_size ||
        mapped.entry_rva != image.entry_rva || mapped.timestamp != image.timestamp ||
        mapped.checksum != image.checksum)
        return status < 0 ? status : status_invalid_image;

    // Windows still uses the original view even after its loader switches bases.
    base = parent.image_base;
    memcpy(peb + 0x10, &base, sizeof(base));
    saved.Rcx = base + image.entry_rva;
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

} // namespace msys_sandbox_compat
