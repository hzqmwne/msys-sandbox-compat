# ADR-0017 — Adapt explicit process and thread DACLs at creation

[简体中文](../zh-CN/decisions/0017-adapt-process-dacl-at-creation.md)

Status: Accepted
Date: 2026-11-23

Replaces the process and initial-thread DACL readback in [ADR-0008](0008-adapt-requested-object-acls.md).

## Context

MSYS fork builds explicit descriptors for the process and its initial thread in `sec_user_nih` and passes them to `CreateProcessW`. After fork resumes, MSYS skips the cold-start process DACL update. Signal delivery later needs to reopen the process by PID with `PROCESS_DUP_HANDLE`. Removing only the old post-creation update broke cross-process signals under PSEC and FullRestricted.

## Decision

When `process-dacl` is enabled in a restricted context, inspect both supplied object attributes before the original `NtCreateUserProcess` call. Use the ADR-0008 transform and supply an adjusted descriptor in a temporary attribute copy when needed. The same request-based rule applies to native callers in the relay tree. DACL adaptation no longer requires classifying the target image, reading the new objects, or writing their DACLs after creation.

Windows supplies default DACLs when the descriptors are absent, including for standalone launches. MSYS DACL resets on its current process still go through the separate `NtSetSecurityObject` path.

## Validation

Release regressions covered normal and mixed-bitness startup, module switches, PSEC ConPTY, explicit re-entry, relay chains in PSEC and FullRestricted, and the shared ACL transform. A native PSEC control passed the same explicit DACL for both objects. With the module on, the creator reopened both before resume. With it off, both opens were denied. Caller input remained intact and the initial suspend count was 1 in both cases.
