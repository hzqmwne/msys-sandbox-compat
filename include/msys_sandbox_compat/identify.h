#pragma once

#include "native_api.h"
#include <stdint.h>

namespace msys_sandbox_compat {

constexpr size_t image_path_chars = 1024;

enum class ImageKind : uint32_t { executable = 1, library = 2 };

struct ImageRecord {
    uint64_t preferred_base;
    uint32_t image_size;
    ImageKind kind;
};

struct ProcessImage {
    ImageRecord record;
    wchar_t path[image_path_chars];
    bool related;
};

struct MappingInspection {
    HANDLE section;
    bool section_flags;
    bool path_match;
    bool section_base;
};

size_t runtime_root_length(const wchar_t *path, size_t chars);
NTSTATUS identify_process(const NativeApi &api, HANDLE process, ProcessImage &image);
bool imports_msys(const NativeApi &api, const wchar_t *path, size_t chars);
NTSTATUS related_image(const NativeApi &api, HANDLE process, const void *base, const wchar_t *path,
                       size_t path_chars, ImageRecord &image, bool &related,
                       MappingInspection *mapping = nullptr);

} // namespace msys_sandbox_compat
