#include "msys_sandbox_compat/agent.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

using namespace msys_sandbox_compat;
namespace {
int failures = 0;
void check(bool pass, const char *name) {
    std::printf("%s pass=%d\n", name, pass);
    failures += !pass;
}
NativeApi native_api() {
    NativeApi api{};
    auto module = GetModuleHandleW(L"ntdll.dll");
#define RESOLVE(field, symbol)                                                                     \
    api.field = reinterpret_cast<decltype(api.field)>(GetProcAddress(module, symbol))
    RESOLVE(allocate, "NtAllocateVirtualMemory");
    RESOLVE(free, "NtFreeVirtualMemory");
    RESOLVE(read, "NtReadVirtualMemory");
    RESOLVE(write, "NtWriteVirtualMemory");
    RESOLVE(protect, "NtProtectVirtualMemory");
    RESOLVE(query_memory, "NtQueryVirtualMemory");
    RESOLVE(flush_code, "NtFlushInstructionCache");
    RESOLVE(open_file, "NtOpenFile");
    RESOLVE(create_section, "NtCreateSection");
    RESOLVE(map_section, "NtMapViewOfSection");
    RESOLVE(unmap_section, "NtUnmapViewOfSection");
    RESOLVE(close, "NtClose");
#undef RESOLVE
    return api;
}

void creation_attributes(PCWSTR image) {
    constexpr ULONG_PTR image_name = 0x20005, memory_reserve = 0x20007;
    struct Attribute {
        ULONG_PTR type;
        SIZE_T size;
        const void *value;
        SIZE_T *returned;
    };
    struct {
        SIZE_T bytes;
        Attribute entries[70];
    } input{};
    auto path = std::wstring(L"\\??\\") + image;
    for (auto &c : path)
        if (c == L'/')
            c = L'\\';
    input.bytes = sizeof(input);
    input.entries[69] = {image_name, path.size() * sizeof(wchar_t), path.c_str(), nullptr};
    const auto api = native_api();
    HeapReservation reservation(api, &input);
    const auto expanded = static_cast<const decltype(input) *>(reservation.attributes());
    bool pass = expanded != &input && expanded->bytes == sizeof(input) + sizeof(Attribute) &&
                !memcmp(expanded->entries, input.entries, sizeof(input.entries));
    if (pass) {
        auto tail = reinterpret_cast<const Attribute *>(
            reinterpret_cast<const BYTE *>(expanded) + sizeof(input));
        uintptr_t expected[]{msys_heap_base, msys_heap_extent};
        pass = tail->type == memory_reserve && tail->size == sizeof(expected) &&
               !tail->returned && !memcmp(tail->value, expected, sizeof(expected));
    }
    check(pass, "extend-70-creation-attributes");

    input.entries[0] = {memory_reserve, 0, nullptr, nullptr};
    HeapReservation existing(api, &input);
    check(existing.attributes() == &input, "preserve-caller-creation-reservation");
}

void planner_cases() {
    BYTE source[hook_source_bytes]{};
    memset(source, 0x90, sizeof(source));
    const BYTE syscall[] = {0x4c, 0x8b, 0xd1, 0xb8, 1, 0, 0, 0};
    memcpy(source, syscall, sizeof(syscall));
    HookRequest request{0x100000, 0x110000, 0x120000, source, sizeof(source)};
    HookPlan plan{};
    auto result = plan_inline_hook(request, plan);
    check(result == HookPlanError::none && plan.consumed == 8 &&
              !memcmp(plan.trampoline, syscall, sizeof(syscall)),
          "syscall-prefix");
    int32_t offset = 0;
    memcpy(&offset, plan.patch + 1, 4);
    check(plan.patch[0] == 0xe9 && request.target + 5 + offset == request.handler,
          "entry-patch-address");

    const BYTE rip[] = {0x48, 0x8b, 0x05, 0x34, 0x12, 0, 0};
    memcpy(source, rip, sizeof(rip));
    result = plan_inline_hook(request, plan);
    memcpy(&offset, plan.trampoline + 3, 4);
    check(result == HookPlanError::none &&
              request.trampoline + 7 + offset == request.target + 7 + 0x1234,
          "rip-uses-logical-addresses");
    request.trampoline = 0x10000000000ULL;
    check(plan_inline_hook(request, plan) == HookPlanError::range, "rip-out-of-range");
    request.trampoline = 0x120000;
    request.handler = 0x10000000000ULL;
    check(plan_inline_hook(request, plan) == HookPlanError::range, "entry-out-of-range");
    request.handler = 0x110000;

    const BYTE forward[] = {0x75, 2, 0x90, 0x90, 0x90};
    memcpy(source, forward, sizeof(forward));
    check(plan_inline_hook(request, plan) == HookPlanError::none, "internal-forward-branch");
    const BYTE middle[] = {0x75, 1, 0x48, 0x31, 0xc0};
    memcpy(source, middle, sizeof(middle));
    check(plan_inline_hook(request, plan) == HookPlanError::branch, "branch-into-instruction");
    const BYTE backward[] = {0x75, 0x20, 0xeb, 0xfc, 0x90};
    memcpy(source, backward, sizeof(backward));
    check(plan_inline_hook(request, plan) == HookPlanError::branch, "branch-back-over-expansion");
    const BYTE loop[] = {0xe2, 0x20, 0x90, 0x90, 0x90};
    memcpy(source, loop, sizeof(loop));
    check(plan_inline_hook(request, plan) == HookPlanError::branch, "external-loop-rejected");
    const BYTE internal_call[] = {0xe8, 0xfb, 0xff, 0xff, 0xff};
    memcpy(source, internal_call, sizeof(internal_call));
    check(plan_inline_hook(request, plan) == HookPlanError::branch, "call-into-patch-rejected");
    const BYTE vector[] = {0xc5, 0xf8, 0x77, 0x90, 0x90};
    memcpy(source, vector, sizeof(vector));
    check(plan_inline_hook(request, plan) == HookPlanError::instruction, "unsupported-vex");
    const BYTE xbegin[] = {0xc7, 0xf8, 0, 0, 0, 0};
    memcpy(source, xbegin, sizeof(xbegin));
    check(plan_inline_hook(request, plan) == HookPlanError::instruction, "unsupported-xbegin");
    source[0] = 0xcc;
    check(plan_inline_hook(request, plan) == HookPlanError::instruction,
          "breakpoint-entry-rejected");
    memset(source, 0x66, sizeof(source));
    check(plan_inline_hook(request, plan) == HookPlanError::instruction, "overlong-prefixes");
    memset(source, 0x90, sizeof(source));
    source[0] = 0x48;
    source[1] = 0xb8;
    request.source_size = 5;
    check(plan_inline_hook(request, plan) == HookPlanError::instruction, "truncated-instruction");

    auto pages =
        static_cast<BYTE *>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD previous = 0;
    memset(pages + 4091, 0x90, 5);
    VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous);
    request.source = pages + 4091;
    check(plan_inline_hook(request, plan) == HookPlanError::none, "bounded-page-end-input");
    VirtualFree(pages, 0, MEM_RELEASE);
}

using Function = int (*)();
Function predecessor = nullptr;
int visits = 0;
int handler() {
    ++visits;
    return predecessor() + 1;
}
void chained_entries() {
    for (int shape = 0; shape < 5; ++shape) {
        auto page = static_cast<BYTE *>(
            VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        memset(page, 0x90, 4096);
        BYTE *prior = page + 128, *trampoline = page + 256, *bridge = page + 512;
        const BYTE old_handler[] = {0xb8, 41, 0, 0, 0, 0xc3};
        memcpy(prior, old_handler, sizeof(old_handler));
        if (shape == 0) {
            page[0] = 0xe9;
            int32_t offset = 123;
            memcpy(page + 1, &offset, 4);
        } else if (shape == 1) {
            page[0] = 0xeb;
            page[1] = 126;
        } else if (shape == 2) {
            const BYTE jump[] = {0xff, 0x25, 26, 0, 0, 0};
            memcpy(page, jump, sizeof(jump));
            memcpy(page + 32, &prior, 8);
        } else if (shape == 3) {
            page[0] = 0x48;
            page[1] = 0xb8;
            memcpy(page + 2, &prior, 8);
            page[10] = 0xff;
            page[11] = 0xe0;
        } else {
            const BYTE endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
            memcpy(page, endbr, sizeof(endbr));
            memcpy(page + 4, old_handler, sizeof(old_handler));
        }
        // An in-page bridge keeps the public entry's rel32 range independent
        // of where the test EXE and its C++ handler happen to be loaded.
        const BYTE indirect[] = {0xff, 0x25, 0, 0, 0, 0};
        memcpy(bridge, indirect, sizeof(indirect));
        auto destination = &handler;
        memcpy(bridge + 6, &destination, 8);
        HookRequest request{reinterpret_cast<uintptr_t>(page), reinterpret_cast<uintptr_t>(bridge),
                            reinterpret_cast<uintptr_t>(trampoline), page, hook_source_bytes};
        HookPlan plan{};
        bool pass = plan_inline_hook(request, plan) == HookPlanError::none;
        if (pass) {
            memcpy(trampoline, plan.trampoline, sizeof(plan.trampoline));
            predecessor = reinterpret_cast<Function>(trampoline);
            pass = predecessor() == 41;
            memcpy(page, plan.patch, sizeof(plan.patch));
            FlushInstructionCache(GetCurrentProcess(), page, 4096);
            visits = 0;
            pass = pass && reinterpret_cast<Function>(page)() == 42 && visits == 1;
        }
        const char *names[] = {"chain-e9", "chain-eb", "chain-ff25", "chain-mov-jmp",
                               "endbr-entry"};
        check(pass, names[shape]);
        VirtualFree(page, 0, MEM_RELEASE);
    }
}

using ArgumentFunction = int (*)(int);
ArgumentFunction argument_predecessor = nullptr;
int argument_handler(int value) { return argument_predecessor(value) + 1; }

void relocated_operations() {
    for (int operation = 0; operation < 3; ++operation) {
        auto page = static_cast<BYTE *>(
            VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        memset(page, 0x90, 4096);
        const BYTE value[] = {0xb8, 41, 0, 0, 0, 0xc3};
        memcpy(page + 128, value, sizeof(value));
        if (operation == 0) {
            const BYTE load[] = {0x8b, 0x05, 122, 0, 0, 0, 0xc3};
            memcpy(page, load, sizeof(load));
            DWORD data = 41;
            memcpy(page + 128, &data, sizeof(data));
        } else if (operation == 1) {
            const BYTE call[] = {0xe8, 123, 0, 0, 0, 0xc3};
            memcpy(page, call, sizeof(call));
        } else {
            const BYTE conditional[] = {0x85, 0xc9, 0x74, 124, 0x90, 0xb8, 40, 0, 0, 0, 0xc3};
            memcpy(page, conditional, sizeof(conditional));
        }
        const BYTE jump[] = {0xff, 0x25, 0, 0, 0, 0};
        memcpy(page + 512, jump, sizeof(jump));
        const auto handler_address = operation == 2 ? reinterpret_cast<uintptr_t>(&argument_handler)
                                                    : reinterpret_cast<uintptr_t>(&handler);
        memcpy(page + 518, &handler_address, sizeof(handler_address));
        HookRequest request{reinterpret_cast<uintptr_t>(page),
                            reinterpret_cast<uintptr_t>(page + 512),
                            reinterpret_cast<uintptr_t>(page + 256), page, hook_source_bytes};
        HookPlan plan{};
        bool pass = plan_inline_hook(request, plan) == HookPlanError::none;
        if (pass) {
            memcpy(page + 256, plan.trampoline, sizeof(plan.trampoline));
            memcpy(page, plan.patch, sizeof(plan.patch));
            FlushInstructionCache(GetCurrentProcess(), page, 4096);
            if (operation == 2) {
                argument_predecessor = reinterpret_cast<ArgumentFunction>(page + 256);
                auto entry = reinterpret_cast<ArgumentFunction>(page);
                pass = entry(0) == 42 && entry(1) == 41 && argument_predecessor(0) == 41 &&
                       argument_predecessor(1) == 40;
            } else {
                predecessor = reinterpret_cast<Function>(page + 256);
                pass = reinterpret_cast<Function>(page)() == 42 && predecessor() == 41;
            }
        }
        const char *names[] = {"execute-rip-load", "execute-relative-call",
                               "execute-conditional-branch"};
        check(pass, names[operation]);
        VirtualFree(page, 0, MEM_RELEASE);
    }
}

void installer(bool relay) {
    auto api = native_api();
    auto state = std::make_unique<AgentState>();
    auto pages =
        static_cast<BYTE *>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    memset(pages, 0x90, 8192);
    const BYTE original[] = {0xb8, 41, 0, 0, 0, 0xc3};
    const BYTE replacement[] = {0xb8, 42, 0, 0, 0, 0xc3};
    state->native_relay = relay;
    const auto installed = selected_hooks(state->effective_modules(!relay));
    for (size_t i = 0; i < hook_count; ++i) {
        auto target = pages + i * 32, destination = pages + 1024 + i * 32;
        memcpy(target, original, sizeof(original));
        memcpy(destination, replacement, sizeof(replacement));
        state->hooks[i] = {reinterpret_cast<uintptr_t>(target),
                           installed & (1u << i) ? reinterpret_cast<uintptr_t>(destination) : 0,
                           reinterpret_cast<uintptr_t>(pages + 4096 + i * hook_trampoline_bytes)};
    }
    DWORD previous = 0;
    VirtualProtect(pages, 4096, PAGE_EXECUTE_READ, &previous);
    auto status = install_hooks(api, current_process(), *state, installed);
    bool pass = status >= 0 && installed == (relay ? bit(HookId::create_process) : 0x1ffu);
    VirtualProtect(pages + 4096, 4096, PAGE_EXECUTE_READ, &previous);
    FlushInstructionCache(GetCurrentProcess(), pages, 8192);
    for (size_t i = 0; i < hook_count; ++i) {
        const bool patched = (installed & (1u << i)) != 0;
        pass = pass && reinterpret_cast<Function>(state->hooks[i].target)() == (patched ? 42 : 41);
        const auto thunk = state->hooks[i].trampoline;
        pass = pass && (patched ? reinterpret_cast<Function>(thunk)() == 41
                                : *reinterpret_cast<const BYTE *>(thunk) == 0x90);
    }
    auto originals = bind_original_calls(*state, installed);
    visit_hooks(originals, [&](HookId id, const char *, auto entry) {
        const auto &slot = state->hooks[static_cast<size_t>(id)];
        pass = pass && reinterpret_cast<uintptr_t>(entry) ==
                           (installed & bit(id) ? slot.trampoline : slot.target);
    });
    MEMORY_BASIC_INFORMATION info{};
    VirtualQuery(pages, &info, sizeof(info));
    pass = pass && info.Protect == PAGE_EXECUTE_READ;
    check(pass, relay ? "installer-relay-scope-and-protection" : "installer-all-and-protection");
    VirtualFree(pages, 0, MEM_RELEASE);
}
} // namespace

int wmain(int argc, wchar_t **argv) {
    if (argc != 2)
        return 2;
    creation_attributes(argv[1]);
    planner_cases();
    chained_entries();
    relocated_operations();
    installer(false);
    installer(true);
    return failures ? 1 : 0;
}
