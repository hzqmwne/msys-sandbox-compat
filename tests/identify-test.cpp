#include "msys_compat/injector.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace msys_compat;
struct Image {
    std::vector<BYTE> bytes = std::vector<BYTE>(0x4000);
};
static std::map<std::wstring, std::unique_ptr<Image>> files;
static size_t maps, allocation_bytes;
static int failures;
static const wchar_t *app = L"\\Device\\Review\\app\\";
static bool fail_allocation, reject_root_reopen;

static Image &image(const std::wstring &name, const std::vector<std::string> &imports,
                    bool dll = true) {
    auto object = std::make_unique<Image>();
    auto &bytes = object->bytes;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x100;
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64 *>(bytes.data() + 0x100);
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
    memcpy(out, source, bytes);
    if (received)
        *received = bytes;
    return 0;
}
static NTSTATUS NTAPI open_file(PHANDLE handle, ACCESS_MASK, POBJECT_ATTRIBUTES attributes,
                                PIO_STATUS_BLOCK, ULONG, ULONG) {
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
    RuntimePaths runtime{};
    wcscpy_s(runtime.directory, L"\\Device\\Review\\runtime\\");
    wcscpy_s(runtime.system_directory, L"\\Device\\Review\\system\\");
    image(L"target.dll", {"msys-2.0.dll"});
    for (int i = 0; i < 8; ++i)
        image(L"common" + std::to_wstring(i) + L".dll",
              i == 7 ? std::vector<std::string>{}
                     : std::vector<std::string>{"common" + std::to_string(i + 1) + ".dll"});
    std::vector<std::string> imports;
    for (int i = 0; i < 16; ++i) {
        image(L"wrapper" + std::to_wstring(i) + L".dll", {"common0.dll"});
        imports.push_back("wrapper" + std::to_string(i) + ".dll");
    }
    auto inspect = [&](const char *label, std::vector<std::string> names) {
        auto &root = image(L"root.exe", names, false);
        maps = allocation_bytes = 0;
        ImageRecord record{};
        std::wstring path = std::wstring(app) + L"root.exe";
        bool related = false;
        auto status = related_image(api, current_process(), root.bytes.data(), path.c_str(),
                                    path.size(), runtime, record, related);
        printf("%s status=%08lx related=%d maps=%zu temporary_bytes=%zu\n", label,
               static_cast<ULONG>(status), related, maps, allocation_bytes);
        return std::make_pair(status, related);
    };
    auto last = imports;
    last.push_back("target.dll");
    auto first = imports;
    first.insert(first.begin(), "target.dll");
    auto expect = [&](bool condition, const char *label) {
        if (!condition) {
            fprintf(stderr, "FAIL: %s\n", label);
            ++failures;
        }
    };
    auto last_result = inspect("shared_graph_target_last", last);
    expect(last_result.first >= 0 && last_result.second, "shared graph, target last");
    auto first_result = inspect("shared_graph_target_first", first);
    expect(first_result.first >= 0 && first_result.second, "shared graph, target first");
    auto native_result = inspect("shared_graph_native", imports);
    expect(native_result.first >= 0 && !native_result.second && maps == 24,
           "each shared dependency is mapped once");
    auto direct = inspect("direct_runtime_import", {"MSYS-2.0.DLL"});
    expect(direct.first >= 0 && direct.second && allocation_bytes == 0,
           "direct imports need no work list");
    reject_root_reopen = true;
    auto reopen = inspect("root_reopen_fails", {"msys-2.0.dll"});
    expect(reopen.first < 0 && reopen.second,
           "preparation failure preserves positive classification");
    reject_root_reopen = false;
    fail_allocation = true;
    direct = inspect("direct_import_without_allocation", {"msys-2.0.dll"});
    expect(direct.first >= 0 && direct.second, "direct imports work without allocating");
    auto unavailable = inspect("indirect_allocation_fails", {"target.dll"});
    expect(unavailable.first < 0 && !unavailable.second,
           "allocation failure is not a native result");
    fail_allocation = false;

    image(L"cycle-a.dll", {"cycle-b.dll"});
    image(L"cycle-b.dll", {"cycle-a.dll"});
    auto cycle = inspect("dependency_cycle", {"cycle-a.dll"});
    expect(cycle.first >= 0 && !cycle.second && maps == 2, "cycles are deduplicated");

    auto &bad = image(L"bad.dll", {"unused.dll"});
    reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(bad.bytes.data() + 0x1000)->Name = 0xfffffff0;
    auto malformed = inspect("malformed_dependency", {"bad.dll"});
    expect(malformed.first < 0 && !malformed.second, "invalid RVA is reported");
    auto direct_last = inspect("direct_import_after_bad_dependency", {"bad.dll", "msys-2.0.dll"});
    expect(direct_last.first >= 0 && direct_last.second && maps == 0,
           "direct imports are checked before dependencies");

    std::vector<std::string> many;
    for (int i = 0; i < 128; ++i) {
        auto name = "node" + std::to_string(i) + ".dll";
        image(std::wstring(name.begin(), name.end()), {});
        many.push_back(name);
    }
    auto limit = inspect("node_limit", many);
    expect(limit.first == status_not_supported && !limit.second, "node limit is observable");

    for (int i = 0; i < 17; ++i)
        image(L"deep" + std::to_wstring(i) + L".dll",
              i == 16 ? std::vector<std::string>{"msys-2.0.dll"}
                      : std::vector<std::string>{"deep" + std::to_string(i + 1) + ".dll"});
    auto depth = inspect("depth_limit", {"deep0.dll"});
    expect(depth.first == status_not_supported && !depth.second, "depth limit is observable");
    printf("IDENTIFY-%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
