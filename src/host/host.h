#pragma once
#include "msys_compat/protocol.h"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace msys_compat {
void check(bool success, const char *operation);
void check_nt(NTSTATUS status, const char *operation);
std::wstring quote(const std::wstring &text);
std::wstring file_path(HANDLE file);
NativeApi resolve_api();
HANDLE configure_security(AgentState &state);
void configure_runtime_paths(const std::filesystem::path &runtime, AgentState &state);
void inject_root(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &state,
                 const std::filesystem::path &agent);
} // namespace msys_compat
