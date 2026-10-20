#include <stddef.h>
#include <stdint.h>

extern "C" __declspec(dllimport) int getpid();
extern "C" __declspec(dllimport) intptr_t write(int, const void *, size_t);

// Zero-argument Perl XSUB: leaving the Perl stack unchanged returns no values.
// This fixture needs no Perl headers or import library, and really calls MSYS.
extern "C" __declspec(dllexport) void late_dep_probe(void *, void *) {
    constexpr char success[] = "LATE-DLL-PASS\n";
    constexpr char failure[] = "LATE-DLL-FAIL\n";
    bool valid = getpid() > 0;
    write(1, valid ? success : failure, sizeof(success) - 1);
}
