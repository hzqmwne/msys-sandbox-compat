// Both the module and its helper are installed after the target starts.
extern "C" __declspec(dllimport) int getpid();
extern "C" __declspec(dllimport) void late_dep_probe(void *, void *);
extern "C" __declspec(dllexport) void late_probe(void *interpreter, void *cv) {
    if (getpid() > 0)
        late_dep_probe(interpreter, cv);
}
