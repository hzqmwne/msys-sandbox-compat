# ADR-0002 — Use public ConPTY APIs inside PSEC and keep a native handle owner

Status: Accepted
Date: 2026-10-20

Related: [ADR-0001](0001-suspended-msys-preparation.md), [ADR-0014](0014-conpty-preserve-redirected-stdio.md). [ADR-0013](0013-default-relay-with-wow64.md) later enabled native relay by default in the session host.

## Context

Redirecting host stdio affected where ConPTY took its initial handles in the tested environment. Combining the first PSEC creation with an external ConPTY also produced inconsistent console references. An ordinary conhost outside PSEC could not write input events as MSYS required, even with readable and writable console handles.

Windows retains the initial console standard handles in its console cleanup state. After MSYS closes and reuses one of those handle values, cleanup can close the reused value. Rendering tests alone do not detect this.

## Decision

Call the public ConPTY API inside PSEC. A native instance of the compatibility host attaches to the console and owns the initial standard handles. It gives copies to the actual MSYS target through explicit startup and inheritance settings.

The agent does not reopen `CONIN$` or `CONOUT$` or add console hooks. At this stage neither the native session host nor conhost received the agent. Out-of-sandbox creation, token duplication, and private console-reference manipulation stayed experimental.

## Consequences

MSYS can close its copies safely. The added native host is another instance of the same EXE. Regression tests exercise console I/O, pipes, fork, job control, and exit status together. This decision did not provide a GUI or VT renderer. Dynamic resize was added later.
