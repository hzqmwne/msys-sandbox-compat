#include "msys_sandbox_compat/identify.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace msys_sandbox_compat;
struct Image {
    std::vector<BYTE> bytes = std::vector<BYTE>(0x4000);
};
static std::map<std::wstring, std::unique_ptr<Image>> files;
static size_t maps, allocation_bytes, memory_reads, file_opens, path_queries;
alignas(void *) static BYTE mock_peb[0x10 + sizeof(void *)];
static int failures;
static const wchar_t *app = L"\\Device\\Review\\app\\";
static bool fail_allocation, reject_root_reopen;

static Image &image(const std::wstring &name, const std::vector<std::string> &imports,
                    bool dll = true, LONG pe_offset = 0x100) {
    auto object = std::make_unique<Image>();
    auto &bytes = object->bytes;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = pe_offset;
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64 *>(bytes.data() + pe_offset);
    pe->Signature = IMAGE_NT_SIGNATURE;
    pe->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    pe->FileHeader.Characteristics = dll ? IMAGE_FILE_DLL : 0;
    pe->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pe->OptionalHeader.SizeOfImage = static_cast<DWORD>(bytes.size());
    pe->OptionalHeader.ImageBase = 0x140000000ULL;
    auto &directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    directory.VirtualAddress = 0x1000;
    directory.Size = static_cast<DWORD>((imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    auto entries = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(bytes.data() + 0x1000);
    DWORD cursor = 0x2000;
    for (size_t i = 0; i < imports.size(); ++i) {
        entries[i].Name = cursor;
        memcpy(bytes.data() + cursor, imports[i].c_str(), imports[i].size() + 1);
        cursor += static_cast<DWORD>(imports[i].size() + 1);
    }
    auto &result = *object;
    files[std::wstring(app) + name] = std::move(object);
    return result;
}

static NTSTATUS NTAPI allocate(HANDLE, PVOID *base, ULONG_PTR, PSIZE_T bytes, ULONG, ULONG) {
    allocation_bytes += *bytes;
    if (fail_allocation)
        return status_unsuccessful;
    *base = VirtualAlloc(nullptr, *bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return *base ? 0 : status_unsuccessful;
}
static NTSTATUS NTAPI free_memory(HANDLE, PVOID *base, PSIZE_T, ULONG) {
    VirtualFree(*base, 0, MEM_RELEASE);
    return 0;
}
static NTSTATUS NTAPI read_memory(HANDLE, const void *source, void *out, SIZE_T bytes,
                                  PSIZE_T received) {
    ++memory_reads;
    memcpy(out, source, bytes);
    if (received)
        *received = bytes;
    return 0;
}
static NTSTATUS NTAPI open_file(PHANDLE handle, ACCESS_MASK, POBJECT_ATTRIBUTES attributes,
                                PIO_STATUS_BLOCK, ULONG, ULONG) {
    ++file_opens;
    auto name = attributes->ObjectName;
    auto path = std::wstring(name->Buffer, name->Length / sizeof(wchar_t));
    if (reject_root_reopen && path == std::wstring(app) + L"root.exe")
        return status_unsuccessful;
    auto found = files.find(path);
    if (found == files.end())
        return static_cast<NTSTATUS>(0xc0000034);
    *handle = reinterpret_cast<HANDLE>(found->second.get());
    return 0;
}
static NTSTATUS NTAPI create_section(PHANDLE section, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                     PLARGE_INTEGER, ULONG, ULONG, HANDLE file) {
    *section = file;
    return 0;
}
static NTSTATUS NTAPI map_section(HANDLE section, HANDLE, PVOID *base, ULONG_PTR, SIZE_T,
                                  PLARGE_INTEGER, PSIZE_T extent, ULONG, ULONG, ULONG) {
    ++maps;
    auto file = reinterpret_cast<Image *>(section);
    *base = file->bytes.data();
    *extent = file->bytes.size();
    return 0;
}
static NTSTATUS NTAPI unmap_section(HANDLE, PVOID) { return 0; }
static NTSTATUS NTAPI close_handle(HANDLE) { return 0; }
static NTSTATUS NTAPI query_process(HANDLE, PROCESSINFOCLASS kind, void *buffer, ULONG bytes,
                                     PULONG) {
    if (kind == ProcessBasicInformation && bytes == sizeof(PROCESS_BASIC_INFORMATION)) {
        auto &info = *static_cast<PROCESS_BASIC_INFORMATION *>(buffer);
        info.PebBaseAddress = reinterpret_cast<PPEB>(mock_peb);
        return status_success;
    }
    if (static_cast<ULONG>(kind) == 27) {
        ++path_queries;
        constexpr wchar_t path[] = L"\\Device\\Review\\app\\root.exe";
        if (bytes < sizeof(UNICODE_STRING) + sizeof(path))
            return status_unsuccessful;
        auto &name = *static_cast<UNICODE_STRING *>(buffer);
        name.Buffer = reinterpret_cast<wchar_t *>(&name + 1);
        name.Length = sizeof(path) - sizeof(wchar_t);
        name.MaximumLength = sizeof(path);
        memcpy(name.Buffer, path, sizeof(path));
        return status_success;
    }
    return status_unsuccessful;
}
static NTSTATUS NTAPI read_file(HANDLE file, HANDLE, void *, void *, PIO_STATUS_BLOCK io, void *out,
                                ULONG bytes, PLARGE_INTEGER offset, PULONG) {
    auto object = reinterpret_cast<Image *>(file);
    if (offset->QuadPart < 0 ||
        static_cast<size_t>(offset->QuadPart) + bytes > object->bytes.size())
        return status_unsuccessful;
    memcpy(out, object->bytes.data() + offset->QuadPart, bytes);
    io->Information = bytes;
    return 0;
}

int main() {
    NativeApi api{};
    api.allocate = allocate;
    api.free = free_memory;
    api.read = read_memory;
    api.query_process = query_process;
    api.open_file = open_file;
    api.create_section = create_section;
    api.map_section = map_section;
    api.unmap_section = unmap_section;
    api.close = close_handle;
    api.read_file = read_file;
    image(L"target.dll", {"msys-2.0.dll"});
    auto inspect = [&](const char *label, std::vector<std::string> names, LONG pe_offset = 0x100) {
        auto &root = image(L"root.exe", names, false, pe_offset);
        maps = allocation_bytes = memory_reads = file_opens = 0;
        ImageRecord record{};
        bool related = false;
        auto status = identify_executable(api, current_process(), root.bytes.data(), record, related);
        printf("%s status=%08lx related=%d maps=%zu temporary_bytes=%zu\n", label,
               static_cast<ULONG>(status), related, maps, allocation_bytes);
        return std::make_pair(status, related);
    };
    auto expect = [&](bool condition, const char *label) {
        if (!condition) {
            fprintf(stderr, "FAIL: %s\n", label);
            ++failures;
        }
    };
    auto indirect = inspect("indirect_runtime_import", {"target.dll"});
    expect(indirect.first >= 0 && !indirect.second && !maps && !file_opens,
           "indirect imports do not classify an executable or open dependencies");
    auto direct = inspect("direct_runtime_import", {"MSYS-2.0.DLL"});
    expect(direct.first >= 0 && direct.second && allocation_bytes == 0,
           "direct imports need no work list");
    expect(memory_reads == 3, "one header read plus the import descriptor and name");
    auto long_header = inspect("pe_header_outside_prefix", {"msys-2.0.dll"}, 0x800);
    expect(long_header.first >= 0 && long_header.second && memory_reads == 4,
           "a later NT header is read separately");
    inspect("process_layout_controls", {"msys-2.0.dll"});
    auto *loaded_root = files.at(std::wstring(app) + L"root.exe")->bytes.data();
    memcpy(mock_peb + 0x10, &loaded_root, sizeof(loaded_root));
    ProcessImage process_image{};
    path_queries = file_opens = allocation_bytes = 0;
    reject_root_reopen = true;
    auto status = identify_process(api, current_process(), process_image, false);
    expect(status >= 0 && process_image.related && !path_queries && !file_opens && !allocation_bytes,
           "disabled EXE placement skips process path lookup and file reopening");
    status = identify_process(api, current_process(), process_image, true);
    expect(status < 0 && process_image.related && path_queries == 1 && file_opens == 1,
           "enabled EXE placement reads metadata and preserves positive classification on failure");
    reject_root_reopen = false;
    fail_allocation = true;
    direct = inspect("direct_import_without_allocation", {"msys-2.0.dll"});
    expect(direct.first >= 0 && direct.second, "direct imports work without allocating");
    fail_allocation = false;

    auto direct_last = inspect("direct_import_after_other", {"target.dll", "msys-2.0.dll"});
    expect(direct_last.first >= 0 && direct_last.second && !maps && !file_opens,
           "classifying a direct import never opens the EXE or its dependencies");
    std::wstring exe_path = std::wstring(app) + L"preflight.exe";
    image(L"preflight.exe", {"target.dll"}, false);
    file_opens = maps = 0;
    expect(!imports_msys(api, exe_path.c_str(), exe_path.size()) && file_opens == 1 && maps == 1,
           "EXE preflight inspects only the named file");
    image(L"preflight.exe", {"msys-2.0.dll"}, false);
    expect(imports_msys(api, exe_path.c_str(), exe_path.size()),
           "EXE preflight recognizes a direct import");
    printf("IDENTIFY-%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
