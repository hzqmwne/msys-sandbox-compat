#pragma once

#include "msys_sandbox_compat/agent.h"

extern "C" __declspec(dllexport) msys_sandbox_compat::AgentState g_agent_state;
extern "C" __declspec(dllexport) BYTE g_agent_thunks[msys_sandbox_compat::hook_count]
                                                    [msys_sandbox_compat::hook_trampoline_bytes];
void register_unwind();
