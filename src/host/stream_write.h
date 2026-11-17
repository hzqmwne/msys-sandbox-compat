#pragma once
#include <windows.h>

namespace msys_sandbox_compat {

inline bool write_all(HANDLE output, const char *buffer, DWORD count,
                      decltype(&::WriteFile) write = ::WriteFile) {
    while (count != 0) {
        DWORD written = 0;
        if (!write(output, buffer, count, &written, nullptr) || written == 0)
            return false;
        buffer += written;
        count -= written;
    }
    return true;
}

} // namespace msys_sandbox_compat
