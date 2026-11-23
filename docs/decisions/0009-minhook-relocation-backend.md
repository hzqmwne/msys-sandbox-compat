# ADR-0009 — Use MinHook's relocation core for ntdll entry points

[简体中文](../zh-CN/decisions/0009-minhook-relocation-backend.md)

Status: Accepted
Date: 2026-10-26

Continues the early-runtime constraints in [ADR-0008](0008-adapt-requested-object-acls.md).

## Context

The original installer relocated eight bytes starting with `mov r10,rcx; mov eax,imm32`. The syscall number could vary, but other valid prologues and existing inline hooks were unsupported. MinHook provided the decoder and relocation code needed for these cases.

## Decision

Vendor MinHook v1.3.4 at revision `c3fcafdc10146beb5919319d0683e44e3c30d537`. Keep HDE64 and headers as supplied and adapt the AMD64 parts of `trampoline.c`. Ship MinHook's BSD 2-Clause license and HDE notices. The runtime manager, allocator, and thread management code are outside this backend.

The backend takes bounded source bytes and logical addresses and produces a plan. The caller installs it in the child. The interface exposes no MinHook types or remote pointer dereferences, and CMake selects the backend. Host and agent build it under their own constraints.

The installer handles newly created, suspended processes. Preparation failure terminates the target. Successful writes restore page protections. Read each child's own entry bytes, preserve existing jump paths, and build its trampolines without reusing private parent addresses. The existing MSYS and native relay scopes continue to apply.

The agent has no CRT initialization, normal or delay imports, TLS, global constructors, `DllMain`, or additional DLL dependencies.

## Consequences

The backend checks decode and buffer limits, displacement reach, and internal branches. Unsupported input returns an error. Instruction coverage and upstream changes are documented in the source tree's `third_party/minhook/README.md`.

Synthetic tests exercise chaining and execution. Compatibility with specific security software requires its own validation. [Testing](../testing.md)
