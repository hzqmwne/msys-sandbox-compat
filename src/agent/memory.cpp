#include <stddef.h>

// No CRT or loader initialization is available when the initial thread enters
// ntdll. Volatile byte loops also prevent MSVC from recognizing and recursively
// lowering these definitions back into their own CRT intrinsic calls.
extern "C" void *__cdecl memcpy(void *target, const void *source, size_t count) {
    auto out = static_cast<volatile unsigned char *>(target);
    auto in = static_cast<const volatile unsigned char *>(source);
    for (size_t i = 0; i < count; ++i)
        out[i] = in[i];
    return target;
}
extern "C" void *__cdecl memset(void *target, int value, size_t count) {
    auto out = static_cast<volatile unsigned char *>(target);
    for (size_t i = 0; i < count; ++i)
        out[i] = static_cast<unsigned char>(value);
    return target;
}
