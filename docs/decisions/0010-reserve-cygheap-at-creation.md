# ADR-0010 — Reserve cygheap at its original address during creation

Status: Superseded by [ADR-0011](0011-release-heap-reservations-before-start.md)
Date: 2026-11-18

Related: [ADR-0001](0001-suspended-msys-preparation.md).

## Context

During fork and exec, AMD64 MSYS reconstructs the parent's cygheap in the child and calculates the committed length relative to a compile-time base. The earlier relocation approach intercepted allocations and had to translate both addresses and lengths.

## Decision

Add `PS_ATTRIBUTE_MEMORY_RESERVE` for `[0x800000000, 0xA00000000)` when creating a recognized MSYS process. The stock runtime encounters a reserved range when it tries to reserve it again, then commits at the original address. The shim checks the reservation and lets MSYS choose the committed address, length, and protections.

Run bounded import preflight on the path in the creation request and verify the actual suspended image. Preserve the caller's attributes and reservations. The standalone host intercepts the current creation through its KernelBase import slot. Descendants and inherited hosts use the agent's creation entry. If preflight is unavailable and the actual image matches, try the reservation before resume.

## Consequences

Windows maps the EXE and system DLLs before the reservation and creates the PEB and initial stack afterward. An earlier conflict can fail creation or preparation. The reservation occupies virtual address space. PSEC token, ASLR flags, and normal Win32 creation semantics come from the original request.

The cygheap range comes from the supported AMD64 runtime layout. There is no public layout query ABI. Preferred image bases come from PE headers. Userheap still needs its own reservation and uses the existing adjustment. Shared mappings, stacks, and the mmap pool keep their own allocation mechanisms.
