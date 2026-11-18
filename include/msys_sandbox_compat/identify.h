#pragma once

#include "native_api.h"
#include <stdint.h>

namespace msys_sandbox_compat {

constexpr size_t image_path_chars = 1024;

enum class ImageKind : uint32_t { executable = 1, library = 2, runtime = 3 };

struct ImageRecord {
    uint64_t preferred_base;
    uint32_t image_size;
    ImageKind kind;
};

// Search hints for indirect imports. Runtime membership is determined by the
// declared msys-2.0.dll import name, without authenticating a particular file.
struct RuntimePaths {
    wchar_t directory[image_path_chars];
    wchar_t system_directory[image_path_chars];
};

struct ProcessImage {
    ImageRecord record;
    wchar_t path[image_path_chars];
    bool related;
};

NTSTATUS identify_process(const NativeApi &api, HANDLE process, const RuntimePaths &runtime,
                          ProcessImage &image);
bool imports_msys(const NativeApi &api, const wchar_t *path, size_t chars,
                  const RuntimePaths &runtime);
NTSTATUS related_image(const NativeApi &api, HANDLE process, const void *base, const wchar_t *path,
                       size_t path_chars, const RuntimePaths &runtime, ImageRecord &image,
                       bool &related, const wchar_t *application_directory = nullptr);

} // namespace msys_sandbox_compat
