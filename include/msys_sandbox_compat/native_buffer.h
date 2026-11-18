#pragma once
#include "native_api.h"

namespace msys_sandbox_compat {
// Per-call storage for hooks running on MSYS's small, guarded internal stacks.
// Uses original NT entry points, requires no CRT heap, and is never shared.
class NativeBuffer {
  public:
    NativeBuffer(const NativeApi &api, SIZE_T bytes) : api_(api) {
        if (bytes && api_.allocate(current_process(), &data_, 0, &bytes, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE) < 0)
            data_ = nullptr;
    }
    ~NativeBuffer() {
        if (!data_)
            return;
        SIZE_T bytes = 0;
        api_.free(current_process(), &data_, &bytes, MEM_RELEASE);
    }
    explicit operator bool() const { return data_ != nullptr; }
    template <class T> T *as() const { return static_cast<T *>(data_); }
    PVOID release() {
        auto data = data_;
        data_ = nullptr;
        return data;
    }
    NativeBuffer(const NativeBuffer &) = delete;
    NativeBuffer &operator=(const NativeBuffer &) = delete;

  private:
    const NativeApi &api_;
    PVOID data_ = nullptr;
};
} // namespace msys_sandbox_compat
