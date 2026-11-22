#pragma once
#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/command_line.h"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace msys_sandbox_compat {
void check(bool success, const char *operation);
void check_nt(NTSTATUS status, const char *operation);
NativeApi resolve_api(const AgentState &state);
AgentState *inherited_agent();
std::wstring require_restricted_context(bool ipc);
HANDLE configure_security(AgentState &state, const std::wstring &session_tag);
BOOL create_root(PCWSTR executable, PWSTR command, STARTUPINFOEXW &startup, bool conpty,
                 const AgentState *state, PROCESS_INFORMATION &child, bool &reserved);
void inject_root(HANDLE process, uint32_t installed, const AgentState &state,
                 const std::filesystem::path &agent);
} // namespace msys_sandbox_compat
