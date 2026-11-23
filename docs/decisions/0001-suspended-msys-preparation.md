# ADR-0001 — Prepare suspended MSYS processes and identify them by import name

[简体中文](../zh-CN/decisions/0001-suspended-msys-preparation.md)

Status: Accepted
Date: 2026-10-20

Partially superseded by [ADR-0004](0004-preserve-sandbox-object-policy.md) for default token DACLs, [ADR-0006](0006-opt-in-native-relay.md) for native relay, [ADR-0012](0012-prefer-dll-image-base-at-map.md) for direct-import recognition, and [ADR-0015](0015-initialize-at-child-loader-entry.md) for child-side initialization.

## Context

In the tested PSEC environment, stock MSYS encountered object access failures, forced ASLR, and conflicts with its fixed heap layout. Fork requires matching parent and child image addresses. Preparation has to occur before runtime initialization, including for programs installed after launch. The prototype occupied the debug channel with debug events and INT3. A fixed list of installation paths would miss newly installed programs.

## Decision

Create the target initially suspended and inspect its actual PE import table. At the time of this decision, a direct or transitive import of `msys-2.0.dll` selected that ABI. The dependency walk was bounded, compared names without regard to case, and returned status separately from a match.

Map an agent with no CRT, normal imports, TLS, or `DllMain` dependency into confirmed MSYS images. Prepare the address layout and eight conditional hooks before resume. Propagate at MSYS child creation while preserving the caller's suspend state. If preparation fails after a positive match, terminate the child and return the error. Report an unclassifiable root as an error and leave unclassifiable descendants untouched.

At this stage, native processes received no agent or compatibility hooks. The shim preserved installation files, ACLs, rebase data, and the target token. The debugger port remained available. PSEC creation used a separate tool.

## Consequences

New packages can be recognized on first launch or mapping without modifying the distribution. AMD64 Native API entries and MSYS internals require regression tests when they change.

Native intermediaries then ended automatic propagation. A native root could enter the shim explicitly. Native descendants of MSYS had additional token and named-object limits. Job notifications track lifetime, while the process creation path controls preparation timing.
