// Classification fixture: declaring the runtime import name is sufficient.
// This DLL lives only in the build directory; no installed file is replaced.
extern "C" __declspec(dllexport) int import_name_marker() { return 7; }
