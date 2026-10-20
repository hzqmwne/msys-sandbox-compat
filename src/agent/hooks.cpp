#include "msys_compat/injector.h"
#include "msys_compat/pe_view.h"
#include "msys_compat/native_buffer.h"
#include <intrin.h>
#include <string.h>
#include <stdlib.h>

using namespace msys_compat;

extern "C" {
__declspec(dllexport) AgentState g_agent_state{};
__declspec(dllexport) uintptr_t g_native_chkstk = 0;
#pragma section(".thunks", read, execute)
__declspec(allocate(".thunks"))
__declspec(dllexport) BYTE g_agent_thunks[hook_count][32] = {{0x90}};
}

namespace {

void register_unwind() {
    auto &state = g_agent_state;
    if (_InterlockedCompareExchange(&state.local.unwind_registered, 1, 0))
        return;
    auto pe = PeView(reinterpret_cast<void *>(state.self_base), state.self_size).headers();
    auto &table = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    state.api.add_function_table(
        reinterpret_cast<PRUNTIME_FUNCTION>(state.self_base + table.VirtualAddress),
        table.Size / sizeof(RUNTIME_FUNCTION), state.self_base);
}

bool starts_with(const wchar_t *value, size_t size, const wchar_t *prefix) {
    size_t index = 0;
    for (; prefix[index]; ++index)
        if (index >= size || wide_lower(value[index]) != wide_lower(prefix[index]))
            return false;
    return true;
}

// Each call owns its attributes and temporary name storage until return;
// there is no persistent scratch allocation or cross-thread reuse.
enum class ObjectKind { object, directory, pipe };

struct ObjectCall {
    OBJECT_ATTRIBUTES attributes{};
    UNICODE_STRING name{};
    PVOID scratch = nullptr;
    bool matched = false;

    bool storage() {
        SIZE_T bytes = 4096;
        return g_agent_state.api.allocate(current_process(), &scratch, 0, &bytes,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0;
    }

    explicit ObjectCall(POBJECT_ATTRIBUTES original, ObjectKind kind = ObjectKind::object) {
        if (!original)
            return;
        attributes = *original;
        auto input = original->ObjectName;
        if (kind == ObjectKind::pipe && (!input || !input->Length)) {
            matched = true;
            return;
        }
        if (!input || !input->Buffer || (input->Length & 1))
            return;
        size_t count = input->Length / 2;
        auto value = input->Buffer;
        auto &state = g_agent_state;
        constexpr wchar_t global[] = L"\\BaseNamedObjects\\";
        constexpr wchar_t session[] = L"\\Sessions\\BNOLINKS\\";
        constexpr wchar_t marker[] = L"session-";
        constexpr size_t global_length = _countof(global) - 1;
        constexpr size_t session_length = _countof(session) - 1;
        size_t suffix = 0, session_end = 0;
        if (kind == ObjectKind::directory && starts_with(value, count, global) &&
            starts_with(value + global_length, count - global_length, L"msys-")) {
            suffix = global_length;
        } else if (kind == ObjectKind::directory && starts_with(value, count, session)) {
            session_end = session_length;
            while (session_end < count && value[session_end] != L'\\')
                ++session_end;
            if (session_end == count ||
                !starts_with(value + session_end + 1, count - session_end - 1, L"msys-"))
                return;
            suffix = session_end + 1;
        } else if (original->RootDirectory && count && value[0] != L'\\') {
            if (!storage())
                return;
            auto status =
                state.api.query_object(original->RootDirectory, 1, scratch, 4096, nullptr);
            if (status < 0)
                return;
            auto root = static_cast<UNICODE_STRING *>(scratch);
            size_t chars = root->Length / 2;
            matched =
                chars > state.root_chars + 6 &&
                wide_equal(root->Buffer, state.root_chars, state.object_root, state.root_chars) &&
                root->Buffer[state.root_chars] == L'\\' &&
                (starts_with(root->Buffer + state.root_chars + 1, chars - state.root_chars - 1,
                             L"msys-") ||
                 starts_with(root->Buffer + state.root_chars + 1, chars - state.root_chars - 1,
                             L"session-"));
            if (kind == ObjectKind::pipe &&
                (wide_equal(root->Buffer, chars, L"\\Device\\NamedPipe", 17) ||
                 wide_equal(root->Buffer, chars, L"\\Device\\NamedPipe\\", 18)))
                matched = true;
            return;
        } else {
            if (kind == ObjectKind::pipe)
                matched = starts_with(value, count, L"\\Device\\NamedPipe\\msys-") ||
                          starts_with(value, count, L"\\??\\pipe\\msys-");
            return;
        }

        // Only a matching directory needs a rewritten name. Keep its buffer
        // off MSYS's small, guarded secondary-thread stacks.
        size_t prefix = state.root_chars + 1;
        if (session_end)
            prefix += _countof(marker) + session_end - session_length;
        if (prefix + count - suffix + 1 > 2048)
            return;
        if (!storage())
            return;
        auto text = static_cast<wchar_t *>(scratch);
        memcpy(text, state.object_root, state.root_chars * sizeof(wchar_t));
        size_t used = state.root_chars;
        text[used++] = L'\\';
        if (session_end) {
            memcpy(text + used, marker, (_countof(marker) - 1) * sizeof(wchar_t));
            used += _countof(marker) - 1;
            for (size_t i = session_length; i < session_end; ++i)
                text[used++] = value[i];
            text[used++] = L'-';
        }
        memcpy(text + used, value + suffix, (count - suffix) * sizeof(wchar_t));
        used += count - suffix;
        text[used] = 0;
        name = {static_cast<USHORT>(used * sizeof(wchar_t)),
                static_cast<USHORT>((used + 1) * sizeof(wchar_t)), text};
        attributes.ObjectName = &name;
        attributes.RootDirectory = nullptr;
        matched = true;
    }

    POBJECT_ATTRIBUTES get(POBJECT_ATTRIBUTES original) {
        if (!matched)
            return original;
        attributes.SecurityDescriptor = g_agent_state.descriptor;
        return &attributes;
    }
    ~ObjectCall() {
        if (scratch) {
            SIZE_T bytes = 0;
            g_agent_state.api.free(current_process(), &scratch, &bytes, MEM_RELEASE);
        }
    }
};

NTSTATUS inspect_section(HANDLE section, ImageRecord &image, bool &related) {
    auto &state = g_agent_state;
    struct SectionBasic {
        PVOID base;
        ULONG attributes;
        LARGE_INTEGER size;
    } basic{};
    auto status = state.api.query_section(section, 0, &basic, sizeof(basic), nullptr);
    if (status < 0 || !(basic.attributes & SEC_IMAGE))
        return status;
    PVOID inspection = nullptr;
    SIZE_T extent = 0;
    status = state.api.map_section(section, current_process(), &inspection, 0, 0, nullptr, &extent,
                                   2, 0, PAGE_READONLY);
    if (status < 0)
        return status;
    NativeBuffer buffer(state.api, 8192);
    status = buffer ? state.api.query_memory(current_process(), inspection, 2, buffer.as<BYTE>(),
                                             8192, nullptr)
                    : status_unsuccessful;
    if (status >= 0) {
        auto name = buffer.as<UNICODE_STRING>();
        status =
            related_image(state.api, current_process(), inspection, name->Buffer, name->Length / 2,
                          state.runtime, image, related, state.application_directory);
    }
    state.api.unmap_section(current_process(), inspection);
    return status;
}

} // namespace

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_directory(PHANDLE handle, ACCESS_MASK access,
                                                               POBJECT_ATTRIBUTES attributes) {
    ObjectCall call(attributes, ObjectKind::directory);
    return g_agent_state.api.create_directory(handle, access, call.get(attributes));
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_section(PHANDLE handle, ACCESS_MASK access,
                                                             POBJECT_ATTRIBUTES attributes,
                                                             PLARGE_INTEGER size, ULONG protection,
                                                             ULONG allocation, HANDLE file) {
    ObjectCall call(attributes);
    return g_agent_state.api.create_section(handle, access, call.get(attributes), size, protection,
                                            allocation, file);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_mutant(PHANDLE handle, ACCESS_MASK access,
                                                            POBJECT_ATTRIBUTES attributes,
                                                            BOOLEAN owner) {
    ObjectCall call(attributes);
    return g_agent_state.api.create_mutant(handle, access, call.get(attributes), owner);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_link(PHANDLE handle, ACCESS_MASK access,
                                                          POBJECT_ATTRIBUTES attributes,
                                                          PUNICODE_STRING target) {
    ObjectCall call(attributes);
    return g_agent_state.api.create_link(handle, access, call.get(attributes), target);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI
hook_pipe(PHANDLE handle, ULONG access, POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK io,
          ULONG share, ULONG disposition, ULONG options, ULONG type, ULONG read_mode,
          ULONG completion, ULONG maximum, ULONG inbound, ULONG outbound, PLARGE_INTEGER timeout) {
    ObjectCall call(attributes, ObjectKind::pipe);
    return g_agent_state.api.create_pipe(handle, access, call.get(attributes), io, share,
                                         disposition, options, type, read_mode, completion, maximum,
                                         inbound, outbound, timeout);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_map(HANDLE section, HANDLE process,
                                                         PVOID *base, ULONG_PTR zero, SIZE_T commit,
                                                         PLARGE_INTEGER offset, PSIZE_T size,
                                                         ULONG inherit, ULONG allocation,
                                                         ULONG protection) {
    auto &state = g_agent_state;
    register_unwind();
    ImageRecord image{};
    bool related = false;
    auto status = inspect_section(section, image, related);
    if (status < 0) {
        agent_log(state, "image classification or preparation failed", static_cast<ULONG>(status));
        if (related)
            return status;
    } else if (related && image.kind != ImageKind::executable) {
        *base = reinterpret_cast<void *>(image.preferred_base);
    }
    status = state.api.map_section(section, process, base, zero, commit, offset, size, inherit,
                                   allocation, protection);
    if (status >= 0 && related) {
        if (image.kind == ImageKind::runtime)
            state.local.runtime_loaded = 1;
        agent_log(state, "fixed image mapping", image.preferred_base);
    }
    return status;
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_allocate(HANDLE process, PVOID *base,
                                                              ULONG_PTR zero, PSIZE_T size,
                                                              ULONG allocation, ULONG protection) {
    auto &state = g_agent_state;
    // MSYS uses the current-process pseudo handle for these private arenas.
    if (process == current_process() && state.local.runtime_loaded) {
        if (reinterpret_cast<uintptr_t>(*base) == original_cygheap) {
            const auto delta = relocated_cygheap - original_cygheap;
            if (*size >= delta)
                *size -= delta;
            if (*size > cygheap_extent)
                return status_not_supported;
            *base = reinterpret_cast<void *>(relocated_cygheap);
        } else if (reinterpret_cast<uintptr_t>(*base) == original_userheap) {
            *base = reinterpret_cast<void *>(relocated_userheap);
        }
    }
    return state.api.allocate(process, base, zero, size, allocation, protection);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_set_token(HANDLE token,
                                                               TOKEN_INFORMATION_CLASS kind,
                                                               void *information, ULONG bytes) {
    auto &state = g_agent_state;
    if (kind == TokenDefaultDacl && information && bytes == sizeof(TOKEN_DEFAULT_DACL)) {
        TOKEN_STATISTICS target{}, primary{};
        ULONG returned = 0;
        if (state.api.query_token(token, TokenStatistics, &target, sizeof(target), &returned) >=
                0 &&
            state.api.query_token(reinterpret_cast<HANDLE>(-4), TokenStatistics, &primary,
                                  sizeof(primary), &returned) >= 0 &&
            target.TokenId.LowPart == primary.TokenId.LowPart &&
            target.TokenId.HighPart == primary.TokenId.HighPart) {
            // MSYS replaces the default ACL during cold initialization. Keep
            // the runner's original policy so native descendants retain IPC
            // and token reopen rights in this same sandbox.
            TOKEN_DEFAULT_DACL preserved{state.token_default_dacl_bytes
                                             ? reinterpret_cast<ACL *>(state.token_default_dacl)
                                             : nullptr};
            return state.api.set_token(token, kind, &preserved, sizeof(preserved));
        }
    }
    return state.api.set_token(token, kind, information, bytes);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI
hook_process(PHANDLE process, PHANDLE thread, ACCESS_MASK process_access, ACCESS_MASK thread_access,
             POBJECT_ATTRIBUTES process_attributes, POBJECT_ATTRIBUTES thread_attributes,
             ULONG process_flags, ULONG thread_flags, PRTL_USER_PROCESS_PARAMETERS parameters,
             void *create_info, void *attributes) {
    auto &state = g_agent_state;
    auto status = state.api.create_process(
        process, thread, process_access, thread_access, process_attributes, thread_attributes,
        process_flags, thread_flags | thread_create_suspended, parameters, create_info, attributes);
    if (status < 0)
        return status;
    NativeBuffer storage(state.api, sizeof(ProcessImage));
    auto image = storage.as<ProcessImage>();
    auto prepared =
        image ? identify_process(state.api, *process, state.runtime, *image) : status_unsuccessful;
    if (prepared < 0) {
        if (image && image->related)
            goto failed;
        agent_log(state, "child classification unavailable; left uninstrumented",
                  static_cast<ULONG>(prepared));
    } else if (image->related) {
        prepared = clone_agent(*process, *thread, *image, state);
        if (prepared < 0)
            goto failed;
        agent_log(state, "injected child", reinterpret_cast<ULONG_PTR>(*process));
    } else {
        agent_log(state, "native child left uninstrumented", reinterpret_cast<ULONG_PTR>(*process));
    }
    if (!(thread_flags & thread_create_suspended)) {
        prepared = state.api.resume(*thread, nullptr);
        if (prepared < 0)
            goto failed;
    }
    return status;

failed:
    agent_log(state, "child preparation failed", static_cast<ULONG>(prepared));
    state.api.terminate(*process, prepared);
    state.api.close(*thread);
    state.api.close(*process);
    *thread = nullptr;
    *process = nullptr;
    return prepared;
}
