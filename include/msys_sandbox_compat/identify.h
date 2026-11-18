#pragma once

#include "native_api.h"
#include <stdint.h>

namespace msys_sandbox_compat {

constexpr size_t image_path_chars = 1024;

struct ImageRecord {
    uint64_t preferred_base;
    uint32_t image_size;
};

struct ProcessImage {
    ImageRecord record;
    wchar_t path[image_path_chars];
    size_t runtime_root_chars;
    bool related;
};

size_t exe_runtime_root_length(const wchar_t *path, size_t chars);
NTSTATUS identify_process(const NativeApi &api, HANDLE process, ProcessImage &image);
bool imports_msys(const NativeApi &api, const wchar_t *path, size_t chars);
NTSTATUS identify_executable(const NativeApi &api, HANDLE process, const void *base,
                             const wchar_t *path, size_t path_chars, ImageRecord &image,
                             bool &related);

} // namespace msys_sandbox_compat
