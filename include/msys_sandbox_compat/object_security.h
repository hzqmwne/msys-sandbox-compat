#pragma once
#include "agent.h"
#include <intrin.h>

namespace msys_sandbox_compat {
// Only relay needs a consistent default-policy snapshot during creation/cloning.
// The child's process-local lock is reset before its initial thread resumes.
class PolicyGuard {
  public:
    explicit PolicyGuard(AgentState &state)
        : lock_(state.native_relay ? &state.local.policy_lock : nullptr) {
        if (lock_)
            while (_InterlockedCompareExchange(lock_, 1, 0))
                _mm_pause();
    }
    ~PolicyGuard() {
        if (lock_)
            _InterlockedExchange(lock_, 0);
    }
    PolicyGuard(const PolicyGuard &) = delete;
    PolicyGuard &operator=(const PolicyGuard &) = delete;

  private:
    volatile LONG *lock_;
};

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

NTSTATUS adapt_kernel_object(const NativeApi &api, HANDLE object, const AgentState &state);
// Called while PolicyGuard is held, after a successful intercepted setting.
void remember_object_policy(AgentState &state);
} // namespace msys_sandbox_compat
