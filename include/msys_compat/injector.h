#pragma once

#include "protocol.h"

namespace msys_compat {

NTSTATUS identify_process(const NativeApi &api, HANDLE process, const RuntimePaths &runtime,
                          ProcessImage &image);
NTSTATUS related_image(const NativeApi &api, HANDLE process, const void *base, const wchar_t *path,
                       size_t path_chars, const RuntimePaths &runtime, ImageRecord &image,
                       bool &related, const wchar_t *application_directory = nullptr);
NTSTATUS protect_agent(const NativeApi &api, HANDLE process, const void *image, AgentState &state);
NTSTATUS install_hooks(const NativeApi &api, HANDLE process, AgentState &state, bool msys);
NTSTATUS check_child_context(const NativeApi &api, HANDLE process, const AgentState &state);
NTSTATUS check_object_policy(const NativeApi &api, HANDLE token, const AgentState &state);
NTSTATUS prepare_process(const NativeApi &api, HANDLE process, HANDLE thread,
                         const ProcessImage &image, AgentState &state);
NTSTATUS clone_agent(HANDLE process, HANDLE thread, const ProcessImage &image, AgentState &source);
void agent_log(const AgentState &state, const char *event, ULONG_PTR number = 0);

} // namespace msys_compat
