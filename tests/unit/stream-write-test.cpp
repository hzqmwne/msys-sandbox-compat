#include "stream_write.h"
#include <cstdio>
#include <initializer_list>

using msys_sandbox_compat::write_all;

struct WriteResult {
    DWORD written;
    BOOL success;
};

struct WriteScript {
    const WriteResult *next;
    const WriteResult *end;
    const char *buffer;
    DWORD size;
    DWORD offset = 0;
    bool valid = true;
};

static BOOL WINAPI scripted_write(HANDLE output, LPCVOID buffer, DWORD count, LPDWORD written,
                                  LPOVERLAPPED overlapped) {
    auto &script = *static_cast<WriteScript *>(output);
    if (script.next == script.end || buffer != script.buffer + script.offset ||
        count != script.size - script.offset || overlapped != nullptr) {
        script.valid = false;
        return FALSE;
    }
    const auto result = *script.next++;
    *written = result.written;
    script.offset += result.written;
    return result.success;
}

static bool check(const char *name, DWORD size, std::initializer_list<WriteResult> results,
                  bool expected_success, DWORD expected_written) {
    const char buffer[] = {'a', '\0', 'b', 'c', 'd'};
    WriteScript script{results.begin(), results.end(), buffer, size};
    const bool success = write_all(&script, buffer, size, scripted_write);
    if (script.valid && script.next == script.end && success == expected_success &&
        script.offset == expected_written)
        return true;
    std::fprintf(stderr, "%s: unexpected write sequence or result\n", name);
    return false;
}

int main() {
    const bool complete = check("complete write", 5, {{5, TRUE}}, true, 5);
    const bool partial =
        check("consecutive short writes", 5, {{2, TRUE}, {1, TRUE}, {2, TRUE}}, true, 5);
    const bool stalled =
        check("zero progress after short write", 5, {{2, TRUE}, {0, TRUE}}, false, 2);
    const bool failed = check("failure after short write", 5, {{2, TRUE}, {0, FALSE}}, false, 2);
    const bool empty = check("empty buffer", 0, {}, true, 0);
    return complete && partial && stalled && failed && empty ? 0 : 1;
}
