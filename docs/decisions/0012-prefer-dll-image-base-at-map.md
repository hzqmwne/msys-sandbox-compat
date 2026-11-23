# ADR-0012 — Prefer the PE base for eligible DLL mappings

[简体中文](../zh-CN/decisions/0012-prefer-dll-image-base-at-map.md)

Status: Accepted
Date: 2026-11-19

Partially supersedes [ADR-0001](0001-suspended-msys-preparation.md) for transitive EXE recognition. Related: [ADR-0011](0011-release-heap-reservations-before-start.md).

## Context

MSYS fork compares actual parent and child addresses for modules registered by the runtime, including some native DLLs. Handling only the runtime or the main EXE's direct DLL dependencies misses Perl's transitive dependencies. Even all static dependencies miss dynamically loaded XS modules. [Image mapping experiments](../testing.md#image-mapping-experiments)

EXE recognition selects full compatibility. At `NtMapViewOfSection`, the loader has already selected the image and the section can supply its metadata. Looking up paths used temporary mappings and could miss modules outside the install root. Walking dependencies needed more files. Passing the parent's DLL list would add matching and propagation requirements for first loads and late modules.

## Decision

Identify the EXE by a direct, ordinary import of `msys-2.0.dll`. Preflight serves the temporary heap reservation. The suspended image determines full compatibility.

In a full compatibility process, query the caller's section for image flags, length, and preferred base. Try the preferred base once for an AMD64 `SEC_IMAGE` DLL without `DYNAMIC_BASE` when the caller leaves `*BaseAddress` zero and the entire range fits the original `ZeroBits`. Do not reopen the file, create a query view, or use a parent DLL list.

Explicit bases, unreadable inputs, ineligible images, and failed section queries use the original request. On a failed preferred-base attempt, restore the original base input and retry the original request once. Keep `ZeroBits` and all other parameters unchanged.

## Consequences

The rule applies equally to eligible native and MSYS DLLs. Windows can still relocate a DLL when the preferred range is occupied. Fork depends on the addresses the parent and child actually receive. Releases with `DYNAMIC_BASE` need separate validation. The current hook covers `NtMapViewOfSection`. `NtMapViewOfSectionEx` is outside this decision.

The normal path maps once. Only a failed preferred-base attempt with a restored input maps a second time. The AMD64 sections and Windows versions need validation. `late-package` covers DLLs outside the root, both `ZeroBits` encodings, explicit bases, the dynamic-base flag, and conflict fallback in Perl parents and children. [DLL mapping](../design.md#dll-mapping) · [Testing](../testing.md#image-mapping-experiments)

Writable PE sections remain shared by file stream. `BaseNamedObjects` determines named IPC scope. The `.cygwin_` image section has a separate sharing constraint. [Shared MSYS image sections](../compatibility.md#shared-msys-image-sections)
