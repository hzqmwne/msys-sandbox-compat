#include <windows.h>
#include <cstdio>
extern "C" __declspec(dllimport) int import_name_marker();
int main() {
    auto code = reinterpret_cast<const BYTE *>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateUserProcess"));
    bool injected = code && code[0] == 0xe9;
    printf("IMPORT-NAME-MATCH marker=%d injected=%d\n", import_name_marker(), injected);
    return injected && import_name_marker() == 7 ? 0 : 1;
}
