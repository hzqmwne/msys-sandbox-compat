#pragma once

#include "native_api.h"
#include <stdint.h>

namespace msys_sandbox_compat {

constexpr size_t image_path_chars = 1024;

struct ImageRecord {
    uint32_t image_size;
    uint32_t entry_rva;
    uint32_t timestamp;
    uint32_t checksum;
    bool dynamic_base;
};

NTSTATUS identify_process(const NativeApi &api, HANDLE process, bool &related,
                          ImageRecord *record = nullptr);
NTSTATUS query_wow64_process(const NativeApi &api, HANDLE process, bool &wow64);
bool imports_msys(const NativeApi &api, const wchar_t *path, size_t chars);
NTSTATUS identify_executable(const NativeApi &api, HANDLE process, const void *base,
                             ImageRecord &image, bool &related);

} // namespace msys_sandbox_compat
