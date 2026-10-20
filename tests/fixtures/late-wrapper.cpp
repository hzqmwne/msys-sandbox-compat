// The exported module has no direct MSYS import. Discovery must follow this
// dependency, which also appears only after the target has started.
extern "C" __declspec(dllimport) void late_dep_probe(void *, void *);
extern "C" __declspec(dllexport) void late_probe(void *interpreter, void *cv) {
    late_dep_probe(interpreter, cv);
}
