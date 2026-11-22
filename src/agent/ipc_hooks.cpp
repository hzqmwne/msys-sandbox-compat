#include "agent_runtime.h"

#include "msys_sandbox_compat/pe_view.h"
#include "msys_sandbox_compat/object_security.h"
#include <stdlib.h>
#include <string.h>

using namespace msys_sandbox_compat;

namespace {

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
    SecurityAdaptation security{g_agent_state.api};
    NTSTATUS status = status_success;

    bool storage() {
        SIZE_T bytes = 4096;
        return g_agent_state.api.allocate(current_process(), &scratch, 0, &bytes,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0;
    }

    explicit ObjectCall(POBJECT_ATTRIBUTES original, ObjectKind kind = ObjectKind::object) {
        register_unwind();
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
            auto queried =
                state.api.query_object(original->RootDirectory, 1, scratch, 4096, nullptr);
            if (queried < 0)
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
        status = security.descriptor(attributes.SecurityDescriptor, g_agent_state);
        if (security.adapted_descriptor())
            attributes.SecurityDescriptor = security.adapted_descriptor();
        return &attributes;
    }
    ~ObjectCall() {
        if (scratch) {
            SIZE_T bytes = 0;
            g_agent_state.api.free(current_process(), &scratch, &bytes, MEM_RELEASE);
        }
    }
};
} // namespace

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_directory(PHANDLE handle, ACCESS_MASK access,
                                                               POBJECT_ATTRIBUTES attributes) {
    ObjectCall call(attributes, ObjectKind::directory);
    auto adjusted = call.get(attributes);
    return call.status < 0 ? call.status
                           : g_agent_state.api.create_directory(handle, access, adjusted);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_section(PHANDLE handle, ACCESS_MASK access,
                                                             POBJECT_ATTRIBUTES attributes,
                                                             PLARGE_INTEGER size, ULONG protection,
                                                             ULONG allocation, HANDLE file) {
    ObjectCall call(attributes);
    auto adjusted = call.get(attributes);
    return call.status < 0 ? call.status
                           : g_agent_state.api.create_section(handle, access, adjusted, size,
                                                              protection, allocation, file);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_mutant(PHANDLE handle, ACCESS_MASK access,
                                                            POBJECT_ATTRIBUTES attributes,
                                                            BOOLEAN owner) {
    ObjectCall call(attributes);
    auto adjusted = call.get(attributes);
    return call.status < 0 ? call.status
                           : g_agent_state.api.create_mutant(handle, access, adjusted, owner);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI hook_link(PHANDLE handle, ACCESS_MASK access,
                                                          POBJECT_ATTRIBUTES attributes,
                                                          PUNICODE_STRING target) {
    ObjectCall call(attributes);
    auto adjusted = call.get(attributes);
    return call.status < 0 ? call.status
                           : g_agent_state.api.create_link(handle, access, adjusted, target);
}

extern "C" __declspec(dllexport) NTSTATUS NTAPI
hook_pipe(PHANDLE handle, ULONG access, POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK io,
          ULONG share, ULONG disposition, ULONG options, ULONG type, ULONG read_mode,
          ULONG completion, ULONG maximum, ULONG inbound, ULONG outbound, PLARGE_INTEGER timeout) {
    ObjectCall call(attributes, ObjectKind::pipe);
    auto adjusted = call.get(attributes);
    return call.status < 0
               ? call.status
               : g_agent_state.api.create_pipe(handle, access, adjusted, io, share, disposition,
                                               options, type, read_mode, completion, maximum,
                                               inbound, outbound, timeout);
}
