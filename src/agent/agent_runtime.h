#pragma once

#include "msys_sandbox_compat/agent.h"

extern "C" __declspec(dllexport) msys_sandbox_compat::AgentState g_agent_state;
void register_unwind();
