#pragma once

#include "native_api.h"
#include <stdint.h>

namespace msys_compat {

constexpr size_t image_path_chars = 1024;
constexpr size_t object_root_chars = 512;
constexpr size_t descriptor_bytes = 1024;

constexpr uintptr_t original_cygheap = 0x800000000ULL;
constexpr uintptr_t relocated_cygheap = 0x80000000000ULL;
constexpr size_t cygheap_extent = 0x200000000ULL;
constexpr uintptr_t original_userheap = 0xa00000000ULL;
constexpr uintptr_t relocated_userheap = relocated_cygheap + 0x400000000ULL;

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

enum class HookId : size_t {
    directory,
    section,
    mutant,
    symbolic_link,
    named_pipe,
    map_view,
    allocate,
    create_process,
    set_token,
    count
};
constexpr size_t hook_count = static_cast<size_t>(HookId::count);

struct HookSlot {
    uintptr_t target;
    uintptr_t handler;
    uintptr_t trampoline;
};

struct ProcessState {
    volatile LONG runtime_loaded;
    volatile LONG unwind_registered;
};

struct AgentState {
    uint32_t trace;
    uint32_t native_relay;
    uintptr_t self_base;
    uint32_t self_size;
    NativeApi api;
    RuntimePaths runtime;
    wchar_t application_directory[image_path_chars];
    wchar_t object_root[object_root_chars];
    unsigned char descriptor[descriptor_bytes];
    uint32_t root_chars;
    // Preserve the sandbox's initial default object ACL across MSYS init.
    unsigned char token_default_dacl[2048];
    uint32_t token_default_dacl_bytes;
    HookSlot hooks[hook_count];
    // Process-local fields are reset when cloning into a new suspended child.
    ProcessState local;
};

static_assert(sizeof(void *) == 8, "The agent supports AMD64 only");

} // namespace msys_compat
