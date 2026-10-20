#include "msys_compat/injector.h"
#include "msys_compat/pe_view.h"
#include "msys_compat/native_buffer.h"
#include <string.h>
#include <stdlib.h>

namespace msys_compat {
namespace {

size_t length(const wchar_t *path) {
    size_t size = 0;
    while (path[size])
        ++size;
    return size;
}
size_t directory_length(const wchar_t *path, size_t chars) {
    while (chars && path[chars - 1] != L'\\')
        --chars;
    return chars;
}
bool runtime_name(const wchar_t *path, size_t chars) {
    auto first = directory_length(path, chars);
    constexpr wchar_t name[] = L"msys-2.0.dll";
    return wide_equal(path + first, chars - first, name, _countof(name) - 1);
}
bool os_binding(const char *name) {
    return ascii_equal(name, "ntdll.dll") || ascii_equal(name, "kernel32.dll") ||
           ascii_equal(name, "kernelbase.dll") ||
           (name[0] && name[1] && name[2] && name[3] &&
            ((ascii_lower(name[0]) == 'a' && ascii_lower(name[1]) == 'p' &&
              ascii_lower(name[2]) == 'i' && name[3] == '-') ||
             (ascii_lower(name[0]) == 'e' && ascii_lower(name[1]) == 'x' &&
              ascii_lower(name[2]) == 't' && name[3] == '-')));
}

// Read through ntdll even for local SEC_IMAGE views: an RVA can cross an
// inaccessible section. Keep image parsing off MSYS's guarded thread stacks.
struct ImageReader {
    const NativeApi &api;
    HANDLE process;
    uintptr_t base;
    uint32_t size = 0;
    IMAGE_DATA_DIRECTORY imports{};

    bool read(uint32_t rva, void *output, size_t bytes) const {
        if (size && (rva > size || bytes > size - rva))
            return false;
        SIZE_T received = 0;
        return api.read(process, reinterpret_cast<void *>(base + rva), output, bytes, &received) >=
                   0 &&
               received == bytes;
    }
    bool name(uint32_t rva, char (&text)[256]) const {
        if (rva >= size)
            return false;
        size_t count = size - rva < sizeof(text) ? size - rva : sizeof(text);
        if (read(rva, text, count)) {
            for (size_t i = 0; i < count; ++i)
                if (!text[i])
                    return i != 0;
            return false;
        }
        // Only names next to an unreadable section need individual reads.
        for (uint32_t i = 0; i < count; ++i) {
            if (!read(rva + i, text + i, 1))
                return false;
            if (!text[i])
                return i != 0;
        }
        return false;
    }
    NTSTATUS inspect(const wchar_t *path, size_t chars, ImageRecord &image, bool &related,
                     bool &indirect) {
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 pe{};
        if (!read(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
            dos.e_lfanew > 0x100000 ||
            !read(static_cast<uint32_t>(dos.e_lfanew), &pe, sizeof(pe)) ||
            pe.Signature != IMAGE_NT_SIGNATURE ||
            pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return status_invalid_image;
        size = pe.OptionalHeader.SizeOfImage;
        imports = pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (size < sizeof(pe) || static_cast<uint32_t>(dos.e_lfanew) > size - sizeof(pe) ||
            imports.VirtualAddress > size || imports.Size > size - imports.VirtualAddress)
            return status_invalid_image;
        image = {pe.OptionalHeader.ImageBase, size,
                 pe.FileHeader.Characteristics & IMAGE_FILE_DLL ? ImageKind::library
                                                                : ImageKind::executable};
        if (image.kind == ImageKind::library && runtime_name(path, chars)) {
            image.kind = ImageKind::runtime;
            related = true;
            return status_success;
        }
        char text[256];
        for (uint32_t offset = 0; imports.Size - offset >= sizeof(IMAGE_IMPORT_DESCRIPTOR);
             offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR entry{};
            if (!read(imports.VirtualAddress + offset, &entry, sizeof(entry)))
                return status_invalid_image;
            if (!entry.Name)
                break;
            if (!name(entry.Name, text))
                return status_invalid_image;
            if (ascii_equal(text, "msys-2.0.dll")) {
                related = true;
                return status_success;
            }
            indirect |= !os_binding(text);
        }
        return status_success;
    }
};

struct Dependency {
    const NativeApi &api;
    HANDLE file = nullptr;
    void *view = nullptr;

    NTSTATUS open(const wchar_t *path, size_t chars) {
        UNICODE_STRING name{static_cast<USHORT>(chars * 2), static_cast<USHORT>(chars * 2),
                            const_cast<PWSTR>(path)};
        OBJECT_ATTRIBUTES attributes{};
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        IO_STATUS_BLOCK io{};
        return api.open_file(&file, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                             &attributes, &io,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    }
    NTSTATUS map() {
        HANDLE section = nullptr;
        auto status = api.create_section(&section, SECTION_MAP_READ | SECTION_QUERY, nullptr,
                                         nullptr, PAGE_READONLY, SEC_IMAGE, file);
        if (status < 0)
            return status;
        SIZE_T extent = 0;
        status = api.map_section(section, current_process(), &view, 0, 0, nullptr, &extent, 2, 0,
                                 PAGE_READONLY);
        api.close(section);
        return status;
    }
    NTSTATUS preferred_base(uint64_t &base) const {
        IO_STATUS_BLOCK io{};
        LARGE_INTEGER offset{};
        IMAGE_DOS_HEADER dos{};
        auto status = api.read_file(file, nullptr, nullptr, nullptr, &io, &dos, sizeof(dos),
                                    &offset, nullptr);
        if (status < 0)
            return status;
        if (io.Information != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew < 0 || dos.e_lfanew > 0x100000)
            return status_invalid_image;
        offset.QuadPart = dos.e_lfanew;
        IMAGE_NT_HEADERS64 pe{};
        status =
            api.read_file(file, nullptr, nullptr, nullptr, &io, &pe, sizeof(pe), &offset, nullptr);
        if (status < 0)
            return status;
        if (io.Information != sizeof(pe) || pe.Signature != IMAGE_NT_SIGNATURE ||
            pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return status_invalid_image;
        base = pe.OptionalHeader.ImageBase;
        return status_success;
    }
    ~Dependency() {
        if (view)
            api.unmap_section(current_process(), view);
        if (file)
            api.close(file);
    }
};

// One bounded work list is also the visited set. Each dependency is mapped
// once, then released; traversal never nests mappings or C++ calls.
struct ImportNode {
    wchar_t path[image_path_chars];
    unsigned depth;
};
struct ImportWalk {
    ImportNode nodes[128];
    unsigned count;
    wchar_t application[image_path_chars];
    wchar_t candidate[image_path_chars];

    bool seen(const wchar_t *path, size_t chars) const {
        for (unsigned i = 0; i < count; ++i)
            if (wide_equal(path, chars, nodes[i].path, length(nodes[i].path)))
                return true;
        return false;
    }
    NTSTATUS append(const NativeApi &api, const RuntimePaths &runtime, const char *name,
                    const ImportNode &importer) {
        size_t name_chars = 0;
        while (name[name_chars]) {
            if (name[name_chars] == '/' || name[name_chars] == '\\' || name[name_chars] == ':')
                return status_not_supported;
            ++name_chars;
        }
        const wchar_t *directories[] = {application, importer.path, runtime.directory};
        size_t counts[] = {length(application),
                           directory_length(importer.path, length(importer.path)),
                           length(runtime.directory)};
        for (size_t i = 0; i < _countof(directories); ++i) {
            if (!counts[i])
                continue;
            if (counts[i] + name_chars + 2 > image_path_chars)
                return status_not_supported;
            memcpy(candidate, directories[i], counts[i] * sizeof(wchar_t));
            size_t used = counts[i];
            if (candidate[used - 1] != L'\\')
                candidate[used++] = L'\\';
            for (size_t j = 0; j < name_chars; ++j)
                candidate[used++] = static_cast<unsigned char>(name[j]);
            candidate[used] = 0;
            auto system_chars = length(runtime.system_directory);
            if (seen(candidate, used) ||
                (used >= system_chars &&
                 wide_equal(candidate, system_chars, runtime.system_directory, system_chars)))
                return status_success;
            Dependency file{api};
            auto status = file.open(candidate, used);
            if (status == static_cast<NTSTATUS>(0xc0000034) ||
                status == static_cast<NTSTATUS>(0xc000003a) ||
                status == static_cast<NTSTATUS>(0xc000000f))
                continue;
            if (status < 0)
                return status;
            if (count == _countof(nodes) || importer.depth == 15)
                return status_not_supported;
            auto &node = nodes[count++];
            memcpy(node.path, candidate, (used + 1) * sizeof(wchar_t));
            node.depth = importer.depth + 1;
            return status_success;
        }
        return status_success; // Remaining bindings are outside the supported search directories.
    }
    NTSTATUS imports(const NativeApi &api, const RuntimePaths &runtime, ImageReader &reader,
                     const ImportNode &importer) {
        char name[256];
        for (uint32_t offset = 0; reader.imports.Size - offset >= sizeof(IMAGE_IMPORT_DESCRIPTOR);
             offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR entry{};
            if (!reader.read(reader.imports.VirtualAddress + offset, &entry, sizeof(entry)))
                return status_invalid_image;
            if (!entry.Name)
                break;
            if (!reader.name(entry.Name, name))
                return status_invalid_image;
            if (!os_binding(name)) {
                auto status = append(api, runtime, name, importer);
                if (status < 0)
                    return status;
            }
        }
        return status_success;
    }
};

NTSTATUS indirect_imports(const NativeApi &api, const RuntimePaths &runtime, ImageReader root,
                          const wchar_t *path, size_t chars, const wchar_t *application,
                          bool &related) {
    NativeBuffer memory(api, sizeof(ImportWalk));
    if (!memory)
        return status_unsuccessful;
    auto walk = memory.as<ImportWalk>();
    auto app_chars = application ? length(application) : directory_length(path, chars);
    if (chars >= image_path_chars || app_chars >= image_path_chars)
        return status_not_supported;
    memcpy(walk->application, application ? application : path, app_chars * sizeof(wchar_t));
    memcpy(walk->nodes[0].path, path, chars * sizeof(wchar_t));
    walk->count = 1;
    auto status = walk->imports(api, runtime, root, walk->nodes[0]);
    for (unsigned next = 1; status >= 0 && next < walk->count; ++next) {
        auto &node = walk->nodes[next];
        Dependency file{api};
        status = file.open(node.path, length(node.path));
        if (status < 0)
            break;
        status = file.map();
        if (status < 0)
            break;
        ImageReader reader{api, current_process(), reinterpret_cast<uintptr_t>(file.view)};
        ImageRecord image{};
        bool indirect = false;
        status = reader.inspect(node.path, length(node.path), image, related, indirect);
        if (status < 0 || related)
            break;
        if (indirect)
            status = walk->imports(api, runtime, reader, node);
    }
    return status;
}

} // namespace

NTSTATUS related_image(const NativeApi &api, HANDLE process, const void *base, const wchar_t *path,
                       size_t chars, const RuntimePaths &runtime, ImageRecord &image, bool &related,
                       const wchar_t *application) {
    related = false;
    bool indirect = false;
    ImageReader reader{api, process, reinterpret_cast<uintptr_t>(base)};
    auto status = reader.inspect(path, chars, image, related, indirect);
    if (status >= 0 && !related && indirect)
        status = indirect_imports(api, runtime, reader, path, chars, application, related);
    if (status < 0 || !related)
        return status;
    // SEC_IMAGE may rewrite ImageBase. Recover the preferred address only
    // after classification; a preparation failure must preserve that result.
    Dependency file{api};
    status = file.open(path, chars);
    return status < 0 ? status : file.preferred_base(image.preferred_base);
}

NTSTATUS identify_process(const NativeApi &api, HANDLE process, const RuntimePaths &runtime,
                          ProcessImage &image) {
    image.related = false;
    NativeBuffer buffer(api, 4096);
    if (!buffer)
        return status_unsuccessful;
    auto status = api.query_process(process, static_cast<PROCESSINFOCLASS>(27), buffer.as<BYTE>(),
                                    4096, nullptr);
    if (status < 0)
        return status;
    auto name = buffer.as<UNICODE_STRING>();
    auto chars = name->Length / 2;
    if (chars >= image_path_chars)
        return status_not_supported;
    memcpy(image.path, name->Buffer, name->Length);
    image.path[chars] = 0;
    PROCESS_BASIC_INFORMATION basic{};
    status = api.query_process(process, ProcessBasicInformation, &basic, sizeof(basic), nullptr);
    if (status < 0)
        return status;
    void *base = nullptr;
    status = api.read(process, reinterpret_cast<BYTE *>(basic.PebBaseAddress) + 0x10, &base,
                      sizeof(base), nullptr);
    if (status < 0)
        return status;
    return related_image(api, process, base, image.path, chars, runtime, image.record,
                         image.related);
}
} // namespace msys_compat
