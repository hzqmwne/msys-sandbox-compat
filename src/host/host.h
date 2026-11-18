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
std::wstring file_path(HANDLE file);
NativeApi resolve_api();
AgentState *inherited_agent();
std::wstring require_restricted_context();
HANDLE configure_security(AgentState &state, const std::wstring &session_tag);
void configure_runtime_paths(const std::filesystem::path &runtime, AgentState &state);
BOOL create_root(PCWSTR executable, PWSTR command, STARTUPINFOEXW &startup, bool conpty,
                 const AgentState *state, PROCESS_INFORMATION &child, bool &reserved);
void inject_root(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &state,
                 const std::filesystem::path &agent);
} // namespace msys_sandbox_compat
