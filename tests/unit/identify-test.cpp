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
static size_t maps, allocation_bytes, memory_reads, file_opens;
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
        std::wstring path = std::wstring(app) + L"root.exe";
        bool related = false;
        auto status = identify_executable(api, current_process(), root.bytes.data(), path.c_str(),
                                          path.size(), record, related);
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
    reject_root_reopen = true;
    auto reopen = inspect("root_reopen_fails", {"msys-2.0.dll"});
    expect(reopen.first < 0 && reopen.second,
           "preparation failure preserves positive classification");
    reject_root_reopen = false;
    fail_allocation = true;
    direct = inspect("direct_import_without_allocation", {"msys-2.0.dll"});
    expect(direct.first >= 0 && direct.second, "direct imports work without allocating");
    fail_allocation = false;

    auto direct_last = inspect("direct_import_after_other", {"target.dll", "msys-2.0.dll"});
    expect(direct_last.first >= 0 && direct_last.second && !maps && file_opens == 1,
           "direct imports never open dependencies");
    std::wstring exe_path = std::wstring(app) + L"preflight.exe";
    image(L"preflight.exe", {"target.dll"}, false);
    file_opens = maps = 0;
    expect(!imports_msys(api, exe_path.c_str(), exe_path.size()) && file_opens == 1 && maps == 1,
           "EXE preflight inspects only the named file");
    image(L"preflight.exe", {"msys-2.0.dll"}, false);
    expect(imports_msys(api, exe_path.c_str(), exe_path.size()),
           "EXE preflight recognizes a direct import");
    constexpr wchar_t exe_in_bin[] =
        L"\\Device\\HarddiskVolume7\\Git\\UsR\\BiN\\bash.exe";
    constexpr wchar_t expected_root[] = L"\\Device\\HarddiskVolume7\\Git\\";
    expect(exe_runtime_root_length(exe_in_bin, _countof(exe_in_bin) - 1) ==
               _countof(expected_root) - 1,
           "derive the installation root including its directory separator");
    constexpr wchar_t exe_in_lib[] = L"\\Device\\HarddiskVolume7\\Git\\usr\\lib\\ssh\\sftp-server.exe";
    expect(exe_runtime_root_length(exe_in_lib, _countof(exe_in_lib) - 1) ==
               _countof(expected_root) - 1,
           "recognize executables elsewhere in the usr tree");
    constexpr wchar_t exe_at_volume_root[] = L"\\Device\\HarddiskVolume7\\usr\\bin\\bash.exe";
    expect(!exe_runtime_root_length(exe_at_volume_root, _countof(exe_at_volume_root) - 1),
           "never use an entire NT volume as the root");
    constexpr wchar_t loose_exe[] = L"\\Device\\HarddiskVolume7\\portable\\bash.exe";
    expect(!exe_runtime_root_length(loose_exe, _countof(loose_exe) - 1),
           "nonstandard layout does not enable directory classification");

    printf("IDENTIFY-%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
