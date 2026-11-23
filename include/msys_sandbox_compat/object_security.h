#pragma once
#include "agent.h"

namespace msys_sandbox_compat {
// Owns only an adapted DACL. Other SD fields still refer to this synchronous
// call's original input. No CRT heap or loader-dependent security helpers.
class SecurityAdaptation {
  public:
    explicit SecurityAdaptation(const NativeApi &api) : api_(api) {}
    ~SecurityAdaptation();
    SecurityAdaptation(const SecurityAdaptation &) = delete;
    SecurityAdaptation &operator=(const SecurityAdaptation &) = delete;
    NTSTATUS acl(PACL input, const AgentState &state);
    NTSTATUS descriptor(PSECURITY_DESCRIPTOR input, const AgentState &state);
    PACL adapted_acl() const { return static_cast<PACL>(memory_); }
    PSECURITY_DESCRIPTOR adapted_descriptor() { return memory_ ? &descriptor_ : nullptr; }

  private:
    const NativeApi &api_;
    PVOID memory_ = nullptr;
    SECURITY_DESCRIPTOR descriptor_{};
};

} // namespace msys_sandbox_compat
