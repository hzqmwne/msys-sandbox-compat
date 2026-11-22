#pragma once

#include <windows.h>
#include <stdint.h>

namespace msys_sandbox_compat {

inline unsigned char ascii_lower(unsigned char value) {
    return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

inline bool ascii_equal(const char *left, const char *right) {
    while (*left && *right) {
        if (ascii_lower(*left++) != ascii_lower(*right++))
            return false;
    }
    return *left == *right;
}

inline wchar_t wide_lower(wchar_t value) {
    return value >= L'A' && value <= L'Z' ? value + (L'a' - L'A') : value;
}

inline bool wide_equal(const wchar_t *left, size_t left_size, const wchar_t *right,
                       size_t right_size) {
    if (left_size != right_size)
        return false;
    for (size_t index = 0; index < left_size; ++index) {
        if (wide_lower(left[index]) != wide_lower(right[index]))
            return false;
    }
    return true;
}

// Bounds-checked view of an image-layout PE (not raw-file offsets). The same
// parser is used by runtime validation, payload mapping and injection.
class PeView {
  public:
    PeView(const void *base, size_t extent)
        : base_(static_cast<const unsigned char *>(base)), extent_(extent) {}

    const IMAGE_NT_HEADERS64 *headers() const {
        auto dos = at<IMAGE_DOS_HEADER>(0);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
            return nullptr;
        auto pe = at<IMAGE_NT_HEADERS64>(static_cast<size_t>(dos->e_lfanew));
        if (!pe || pe->Signature != IMAGE_NT_SIGNATURE ||
            pe->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pe->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return nullptr;
        return pe;
    }

    template <class T> const T *at(size_t offset, size_t count = 1) const {
        if (offset > extent_ || count > (extent_ - offset) / sizeof(T))
            return nullptr;
        return reinterpret_cast<const T *>(base_ + offset);
    }

    const IMAGE_SECTION_HEADER *sections(const IMAGE_NT_HEADERS64 &pe) const {
        if (pe.FileHeader.SizeOfOptionalHeader < sizeof(pe.OptionalHeader))
            return nullptr;
        const auto offset = reinterpret_cast<const unsigned char *>(&pe.OptionalHeader) - base_;
        return at<IMAGE_SECTION_HEADER>(offset + pe.FileHeader.SizeOfOptionalHeader,
                                        pe.FileHeader.NumberOfSections);
    }

    const char *string_at(size_t rva) const {
        auto text = at<char>(rva);
        if (!text)
            return nullptr;
        for (size_t index = rva; index < extent_; ++index)
            if (!base_[index])
                return text;
        return nullptr;
    }

    uint32_t exported_rva(const char *wanted) const {
        auto pe = headers();
        if (!pe)
            return 0;
        const auto &directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        auto exports = at<IMAGE_EXPORT_DIRECTORY>(directory.VirtualAddress);
        if (!directory.Size || !exports)
            return 0;
        auto names = at<DWORD>(exports->AddressOfNames, exports->NumberOfNames);
        auto ordinals = at<WORD>(exports->AddressOfNameOrdinals, exports->NumberOfNames);
        auto functions = at<DWORD>(exports->AddressOfFunctions, exports->NumberOfFunctions);
        if (!names || !ordinals || !functions)
            return 0;
        for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
            auto name = string_at(names[index]);
            if (name && ascii_equal(name, wanted) && ordinals[index] < exports->NumberOfFunctions) {
                auto rva = functions[ordinals[index]];
                // Forwarded exports are strings, not executable entry points.
                if (rva >= directory.VirtualAddress &&
                    rva - directory.VirtualAddress < directory.Size)
                    return 0;
                return at<unsigned char>(rva) ? rva : 0;
            }
        }
        return 0;
    }

  private:
    const unsigned char *base_;
    size_t extent_;
};

} // namespace msys_sandbox_compat
