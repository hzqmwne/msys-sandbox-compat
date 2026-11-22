#include <windows.h>
#include <cstdio>
#include <cstdlib>
extern "C" __declspec(dllimport) int import_name_marker();
int main(int argc, char **argv) {
    const char *entries[] = {
        "NtCreateDirectoryObject", "NtCreateSection", "NtCreateMutant",
        "NtCreateSymbolicLinkObject", "NtCreateNamedPipeFile", "NtMapViewOfSection",
        "NtCreateUserProcess", "NtSetInformationToken", "NtSetSecurityObject",
    };
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    unsigned installed = 0;
    for (unsigned index = 0; index < _countof(entries); ++index) {
        auto code = reinterpret_cast<const BYTE *>(GetProcAddress(ntdll, entries[index]));
        if (code && code[0] == 0xe9)
            installed |= 1u << index;
    }
    const auto expected = argc == 2 ? strtoul(argv[1], nullptr, 16) : 0x1ff;
    const int marker = import_name_marker();
    printf("IMPORT-NAME-MATCH marker=%d hooks=%03x\n", marker, installed);
    return marker == 7 && installed == expected ? 0 : 1;
}
