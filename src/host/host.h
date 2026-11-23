#pragma once
#include "msys_sandbox_compat/agent.h"
#include "msys_sandbox_compat/command_line.h"
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace msys_sandbox_compat {
enum class LogLevel { off, error, warning, info, trace };
bool log_enabled(LogLevel level);
void configure_host_log(LogLevel level, const std::filesystem::path &path);
void host_log(LogLevel level, const char *format, ...);
HANDLE host_log_file();
void configure_agent_log(AgentState &state, bool trace);
void check(bool success, const char *operation);
void check_nt(NTSTATUS status, const char *operation);
void redirect_host_stderr(HANDLE handle);
NativeApi resolve_api(const AgentState &state);
AgentState *inherited_agent();
HANDLE prepare_ipc_directory(AgentState &state);
BOOL create_root(PCWSTR executable, PWSTR command, STARTUPINFOEXW &startup, bool conpty,
                 bool inherit_handles,
                 const AgentState *state, PROCESS_INFORMATION &child, bool &reserved);
void inject_root(HANDLE process, uint32_t installed, const AgentState &state,
                 const std::filesystem::path &agent);
} // namespace msys_sandbox_compat
