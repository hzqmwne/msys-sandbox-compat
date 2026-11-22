#include "agent_runtime.h"
#include <intrin.h>

using namespace msys_sandbox_compat;

namespace {

struct SectionImageInformation {
    PVOID entry;
    ULONG zero_bits;
    SIZE_T stack_reserve;
    SIZE_T stack_commit;
    ULONG subsystem;
    ULONG subsystem_version;
    ULONG operating_system_version;
    USHORT image_characteristics;
    USHORT dll_characteristics;
    USHORT machine;
    BYTE contains_code;
    BYTE image_flags;
    ULONG loader_flags;
    ULONG file_size;
    ULONG checksum;
};
static_assert(sizeof(SectionImageInformation) == 64);

bool within_zero_bits(ULONG_PTR base, SIZE_T size, ULONG_PTR zero) {
    if (!zero)
        return true;
    // AMD64 counts apply to the low 32 bits; a bitmap specifies leading zeros.
    ULONG_PTR limit;
    if (zero <= 21) {
        limit = (ULONG_PTR{1} << (32 - zero)) - 1;
    } else if (zero >= 32) {
        unsigned long top;
        _BitScanReverse64(&top, zero);
        limit = UINTPTR_MAX >> (63 - top);
    } else {
        return false;
    }
    return size && base <= limit && size - 1 <= limit - base;
}

PVOID preferred_view_base(const NativeApi &api, HANDLE section, PVOID *base, ULONG_PTR zero) {
    PVOID requested = nullptr;
    SIZE_T received = 0;
    if (api.read(current_process(), base, &requested, sizeof(requested), &received) < 0 ||
        received != sizeof(requested) || requested)
        return nullptr;

    struct SectionBasic {
        PVOID base;
        ULONG attributes;
        LARGE_INTEGER size;
    } basic{};
    if (api.query_section(section, 0, &basic, sizeof(basic), nullptr) < 0 ||
        !(basic.attributes & SEC_IMAGE))
        return nullptr;

    SectionImageInformation flags{};
    if (api.query_section(section, 1, &flags, sizeof(flags), nullptr) < 0 ||
        flags.machine != IMAGE_FILE_MACHINE_AMD64 || !(flags.image_characteristics & IMAGE_FILE_DLL) ||
        (flags.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
        return nullptr;

    PVOID original = nullptr;
    // SectionOriginalBaseInformation identifies the preferred base of this section.
    if (api.query_section(section, 3, &original, sizeof(original), nullptr) < 0 ||
        !original || (reinterpret_cast<uintptr_t>(original) & 0xffff) ||
        !within_zero_bits(reinterpret_cast<uintptr_t>(original), basic.size.QuadPart, zero))
        return nullptr;
    return original;
}
} // namespace

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_map(HANDLE section, HANDLE process,
                                                         PVOID *base, ULONG_PTR zero, SIZE_T commit,
                                                         PLARGE_INTEGER offset, PSIZE_T size,
                                                         ULONG inherit, ULONG allocation,
                                                         ULONG protection) {
    auto &state = g_agent_state;
    register_unwind();
    const auto &api = state.api;
    const auto map = [&] {
        return api.map_section(section, process, base, zero, commit, offset, size,
                               inherit, allocation, protection);
    };
    // Leave aliased in/out arguments to the original call.
    if (!base || (reinterpret_cast<uintptr_t>(base) % alignof(PVOID)) ||
        base == reinterpret_cast<PVOID *>(offset) || base == reinterpret_cast<PVOID *>(size))
        return map();

    const auto preferred = preferred_view_base(api, section, base, zero);
    if (preferred && api.write(current_process(), base, &preferred, sizeof(preferred), nullptr) >= 0) {
        const auto status = map();
        agent_log(state, "image mapping requested base", reinterpret_cast<ULONG_PTR>(preferred));
        agent_log(state, "image mapping status", static_cast<ULONG>(status));
        if (status >= 0) {
            agent_log(state, "image mapping actual base", reinterpret_cast<ULONG_PTR>(*base));
            return status;
        }
        // Failed maps leave the native in/out fields untouched. Undo our own input change.
        const PVOID unspecified = nullptr;
        const auto restored = api.write(current_process(), base, &unspecified, sizeof(unspecified), nullptr);
        if (restored < 0)
            return restored;
        agent_log(state, "image mapping retry with original base", static_cast<ULONG>(status));
    }
    return map();
}
