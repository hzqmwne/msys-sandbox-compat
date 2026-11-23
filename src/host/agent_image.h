#pragma once

#include "msys_sandbox_compat/agent.h"
#include <array>
#include <filesystem>
#include <vector>

namespace msys_sandbox_compat {
// Keep cold starts within the size already supported by inherited relay lookup.
inline constexpr size_t max_agent_image_size = 1024 * 1024;

struct AgentImage {
    std::vector<BYTE> mapped;
    std::array<uint32_t, hook_count> entries{};
    uint32_t state = 0;
    uint32_t thunks = 0;
    uint32_t stack_probe = 0;

    void relocate(uintptr_t base);
};

AgentImage load_agent_image(const std::filesystem::path &path, uint32_t required_hooks);
AgentImage load_agent_image(const BYTE *bytes, size_t size, uint32_t required_hooks);
} // namespace msys_sandbox_compat
