#include "msys_sandbox_compat/identify.h"
#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/native_buffer.h"
#include <string.h>
#include <stdlib.h>

namespace msys_sandbox_compat {
namespace {

// Read through ntdll even for local SEC_IMAGE views: an RVA can cross an
// inaccessible section. Keep image parsing off MSYS's guarded thread stacks.
struct ImageReader {
    const NativeApi &api;
    HANDLE process;
    uintptr_t base;
    uint32_t size = 0;

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

    NTSTATUS inspect(ImageRecord &image, bool &related) {
        // Most images have both headers in the first kilobyte.
        BYTE headers[1024];
        bool have_prefix = read(0, headers, sizeof(headers));
        IMAGE_DOS_HEADER dos{};
        if (have_prefix)
            memcpy(&dos, headers, sizeof(dos));
        else if (!read(0, &dos, sizeof(dos)))
            return status_invalid_image;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x100000)
            return status_invalid_image;
        auto pe_offset = static_cast<uint32_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 pe{};
        if (have_prefix && pe_offset <= sizeof(headers) - sizeof(pe))
            memcpy(&pe, headers + pe_offset, sizeof(pe));
        else if (!read(pe_offset, &pe, sizeof(pe)))
            return status_invalid_image;
        if (pe.Signature != IMAGE_NT_SIGNATURE || pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return status_invalid_image;
        size = pe.OptionalHeader.SizeOfImage;
        if (size < sizeof(pe) || pe_offset > size - sizeof(pe))
            return status_invalid_image;
        if (pe.FileHeader.Characteristics & IMAGE_FILE_DLL)
            return status_success;
        image = {pe.OptionalHeader.ImageBase, size};
        const auto &imports = pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imports.VirtualAddress > size || imports.Size > size - imports.VirtualAddress)
            return status_invalid_image;
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
        }
        return status_success;
    }
};

struct ImageFile {
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
                                         nullptr, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, file);
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
    ~ImageFile() {
        if (view)
            api.unmap_section(current_process(), view);
        if (file)
            api.close(file);
    }
};

} // namespace

size_t exe_runtime_root_length(const wchar_t *path, size_t chars) {
    constexpr wchar_t volume[] = L"\\Device\\HarddiskVolume";
    constexpr wchar_t usr[] = L"\\usr\\";
    constexpr size_t volume_chars = _countof(volume) - 1;
    constexpr size_t usr_chars = _countof(usr) - 1;
    if (chars >= image_path_chars || chars <= volume_chars + usr_chars ||
        !wide_equal(path, volume_chars, volume, volume_chars))
        return 0;
    size_t start = volume_chars;
    while (start < chars && path[start] != L'\\')
        ++start;
    // Require a directory below the volume and retain the trailing separator.
    for (size_t end = chars - usr_chars; end > start; --end)
        if (wide_equal(path + end, usr_chars, usr, usr_chars))
            return end + 1;
    return 0;
}

bool imports_msys(const NativeApi &api, const wchar_t *path, size_t chars) {
    ImageFile file{api};
    if (file.open(path, chars) < 0 || file.map() < 0)
        return false;
    ImageRecord image{};
    bool related = false;
    ImageReader reader{api, current_process(), reinterpret_cast<uintptr_t>(file.view)};
    return reader.inspect(image, related) >= 0 && related;
}

NTSTATUS identify_executable(const NativeApi &api, HANDLE process, const void *base,
                             const wchar_t *path, size_t chars, ImageRecord &image,
                             bool &related) {
    related = false;
    ImageReader reader{api, process, reinterpret_cast<uintptr_t>(base)};
    auto status = reader.inspect(image, related);
    if (status < 0 || !related)
        return status;
    // Read the on-disk EXE base even if the mapped header was relocated.
    ImageFile file{api};
    status = file.open(path, chars);
    return status < 0 ? status : file.preferred_base(image.preferred_base);
}

NTSTATUS identify_process(const NativeApi &api, HANDLE process, ProcessImage &image) {
    image.related = false;
    image.runtime_root_chars = 0;
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
    status = identify_executable(api, process, base, image.path, chars, image.record, image.related);
    if (status >= 0 && image.related)
        image.runtime_root_chars = exe_runtime_root_length(image.path, chars);
    return status;
}
} // namespace msys_sandbox_compat
