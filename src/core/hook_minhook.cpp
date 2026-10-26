/*
 * Adapted from MinHook v1.3.4 src/trampoline.c.
 * Copyright (C) 2009-2017 Tsuda Kageyu. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "msys_sandbox_compat/inline_hook.h"
#include "minhook/hde/hde64.h"
#include <string.h>

namespace msys_sandbox_compat {
namespace {
bool relative32(uintptr_t from, uintptr_t to, int32_t &result) {
    if (to >= from) {
        if (to - from > INT32_MAX)
            return false;
    } else if (from - to > uintptr_t(INT32_MAX) + 1) {
        return false;
    }
    result = static_cast<int32_t>(to - from);
    return true;
}
bool destination(uintptr_t after, int64_t displacement, uintptr_t &result) {
    if (displacement >= 0) {
        if (UINTPTR_MAX - after < static_cast<uint64_t>(displacement))
            return false;
    } else if (after < static_cast<uint64_t>(-displacement)) {
        return false;
    }
    result = after + displacement;
    return true;
}
void absolute_jump(unsigned char *out, uintptr_t address) {
    const unsigned char code[] = {0xff, 0x25, 0, 0, 0, 0};
    memcpy(out, code, sizeof(code));
    memcpy(out + sizeof(code), &address, sizeof(address));
}
bool padding(const unsigned char *bytes, size_t count) {
    if (!count)
        return true;
    if (*bytes != 0 && *bytes != 0x90 && *bytes != 0xcc)
        return false;
    for (size_t i = 1; i < count; ++i)
        if (bytes[i] != *bytes)
            return false;
    return true;
}
} // namespace

HookPlanError plan_inline_hook(const HookRequest &request, HookPlan &plan) {
    plan = {};
    if (!request.source || request.source_size < hook_patch_bytes ||
        request.source_size > hook_source_bytes || !request.target || !request.handler ||
        !request.trampoline || request.target > UINTPTR_MAX - hook_source_bytes ||
        request.trampoline > UINTPTR_MAX - hook_trampoline_bytes)
        return HookPlanError::input;
    int32_t entry_offset = 0;
    if (!relative32(request.target + hook_patch_bytes, request.handler, entry_offset))
        return HookPlanError::range;
    plan.patch[0] = 0xe9;
    memcpy(plan.patch + 1, &entry_offset, sizeof(entry_offset));

    size_t old_pos = 0, new_pos = 0, instructions = 0;
    uintptr_t branch_end = 0;
    unsigned char old_offsets[8]{}, new_offsets[8]{};
    unsigned char internal_targets[8]{};
    size_t internal_count = 0;
    bool finished = false;
    do {
        unsigned char encoded[32]{};
        const unsigned char *copy = encoded;
        size_t copy_size = 0, length = 0;
        const auto old_ip = request.target + old_pos;
        const auto new_ip = request.trampoline + new_pos;
        if (old_pos >= hook_patch_bytes) {
            absolute_jump(encoded, old_ip);
            copy_size = 14;
            finished = true;
        } else {
            // HDE is unchanged upstream code. Decode only a padded local copy;
            // reject any instruction extending past the actual readable input.
            unsigned char decode[32]{};
            size_t available = request.source_size - old_pos;
            if (available > 15)
                available = 15;
            memcpy(decode, request.source + old_pos, available);
            hde64s hs{};
            length = hde64_disasm(decode, &hs);
            if ((hs.flags & F_ERROR) || !length || length > available || length > 15)
                return HookPlanError::instruction;
            // Stable HDE decodes XBEGIN as C7/imm32 without relocation semantics.
            // Moving an INT3 changes the address seen by a breakpoint handler.
            if ((hs.opcode == 0xc7 && hs.modrm == 0xf8) || hs.opcode == 0xcc)
                return HookPlanError::instruction;
            copy = request.source + old_pos;
            copy_size = length;
            if ((hs.modrm & 0xc7) == 0x05) {
                // Preserve the operand's target, including existing hook pointer
                // slots. No target-process pointer is dereferenced here.
                if (hs.p_67)
                    return HookPlanError::instruction;
                size_t immediate = (hs.flags & 0x3c) >> 2;
                if (length < immediate + 4)
                    return HookPlanError::instruction;
                const size_t offset = length - immediate - 4;
                int32_t before = 0, after = 0;
                uintptr_t address = 0;
                memcpy(&before, copy + offset, sizeof(before));
                if (!destination(old_ip + length, before, address) ||
                    !relative32(new_ip + length, address, after))
                    return HookPlanError::range;
                memcpy(encoded, copy, length);
                memcpy(encoded + offset, &after, sizeof(after));
                copy = encoded;
                if (hs.opcode == 0xff && hs.modrm_reg == 4)
                    finished = true;
            } else if (hs.opcode == 0xe8 || (hs.opcode & 0xfd) == 0xe9 ||
                       (hs.opcode & 0xf0) == 0x70 || (hs.opcode & 0xfc) == 0xe0 ||
                       (hs.opcode == 0x0f && (hs.opcode2 & 0xf0) == 0x80)) {
                const bool call = hs.opcode == 0xe8;
                if (hs.p_66)
                    return HookPlanError::instruction;
                const bool jump = (hs.opcode & 0xfd) == 0xe9;
                const bool loop = (hs.opcode & 0xfc) == 0xe0;
                const bool short_branch = hs.opcode == 0xeb || (hs.opcode & 0xf0) == 0x70 || loop;
                uintptr_t address = 0;
                if (!destination(old_ip + length,
                                 short_branch ? static_cast<int8_t>(hs.imm.imm8)
                                              : static_cast<int32_t>(hs.imm.imm32),
                                 address))
                    return HookPlanError::range;
                const bool internal =
                    address >= request.target && address < request.target + hook_patch_bytes;
                if (!call && internal) {
                    // Upstream preserves internal branch bytes. Reject a branch
                    // back over an expansion as well as forward expansions.
                    if (new_pos != old_pos || internal_count == 8)
                        return HookPlanError::branch;
                    internal_targets[internal_count++] =
                        static_cast<unsigned char>(address - request.target);
                    if (branch_end < address)
                        branch_end = address;
                } else if (call) {
                    if (internal)
                        return HookPlanError::branch;
                    // CALL [RIP+2]; JMP +8; absolute target.
                    const unsigned char head[] = {0xff, 0x15, 2, 0, 0, 0, 0xeb, 8};
                    memcpy(encoded, head, sizeof(head));
                    memcpy(encoded + sizeof(head), &address, sizeof(address));
                    copy = encoded;
                    copy_size = 16;
                } else if (jump) {
                    absolute_jump(encoded, address);
                    copy = encoded;
                    copy_size = 14;
                    finished = old_ip >= branch_end;
                } else if (loop) {
                    return HookPlanError::branch;
                } else {
                    const unsigned char condition =
                        (hs.opcode == 0x0f ? hs.opcode2 : hs.opcode) & 0x0f;
                    encoded[0] = 0x71 ^ condition;
                    encoded[1] = 14;
                    absolute_jump(encoded + 2, address);
                    copy = encoded;
                    copy_size = 16;
                }
            } else if ((hs.opcode & 0xfe) == 0xc2) {
                finished = old_ip >= branch_end;
            }
            if (old_ip < branch_end && copy_size != length)
                return HookPlanError::branch;
        }
        if (instructions == 8 || new_pos + copy_size > hook_trampoline_bytes)
            return HookPlanError::capacity;
        old_offsets[instructions] = static_cast<unsigned char>(old_pos);
        new_offsets[instructions++] = static_cast<unsigned char>(new_pos);
        memcpy(plan.trampoline + new_pos, copy, copy_size);
        new_pos += copy_size;
        old_pos += length;
    } while (!finished);
    if (old_pos < hook_patch_bytes &&
        !padding(request.source + old_pos, hook_patch_bytes - old_pos))
        return HookPlanError::capacity; // No patch-above fallback outside the public entry.
    for (size_t i = 0; i < internal_count; ++i) {
        bool boundary = false;
        for (size_t j = 0; j < instructions; ++j)
            if (old_offsets[j] == internal_targets[i] && new_offsets[j] == old_offsets[j])
                boundary = true;
        if (!boundary)
            return HookPlanError::branch;
    }
    plan.consumed = static_cast<uint8_t>(old_pos);
    return HookPlanError::none;
}

} // namespace msys_sandbox_compat
