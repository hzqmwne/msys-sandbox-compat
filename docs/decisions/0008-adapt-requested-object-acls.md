# ADR-0008 — Adapt the caller's current object ACL

[简体中文](../zh-CN/decisions/0008-adapt-requested-object-acls.md)

Status: Accepted
Date: 2026-10-26

Supersedes the initial-DACL snapshot and descriptor templates in [ADR-0004](0004-preserve-sandbox-object-policy.md). [ADR-0016](0016-drop-relay-default-dacl-baseline.md) later removed the relay baseline and creation lock. [ADR-0017](0017-adapt-process-dacl-at-creation.md) moved explicit process and initial-thread DACL adaptation into the creation call.

## Context

Restoring a whole default ACL snapshot or replacing a descriptor can override access choices in the current request. The prototype showed that the shim could keep the request and add access for the applicable restricted principal.

## Decision

### ACL transform

Keep the ntdll entry points and existing object path selection. The transform is shared in core and can serve calls from outside the MSYS image when the module is active. The original implementation read back the effective DACL for a recognized process or thread before adapting it.

Preserve ordinary allow ACEs, including order and masks. Combine the requested grants to the current user and enabled, non-deny-only groups. Add only the bits the restricted principal still lacks. For AppContainer use the package SID. Otherwise prefer a logon SID present in both enabled and restricting sets, or use a single identifiable, non-broad restricting principal in the initial ACL.

The supported form is an unflagged `ACCESS_ALLOWED_ACE` in `ACL_REVISION`. Pass deny, inherited, object, callback, conditional, and other entries to Windows. Keep empty DACLs empty. Validate ACL and SID bounds and work on a copy. Windows validates unsupported or invalid input. If allocating adaptation storage fails, report that failure.

An explicit NULL DACL means open access, but a shared section with that descriptor could not be reopened by descendants in the tested PSEC. Express that intent as Everyone:GA and restricted-principal:GA. Apply the same rule to a NULL `TokenDefaultDacl`. Missing descriptors or DACLs use Windows defaults and inheritance.

Support absolute and self-relative descriptors, preserving owner, group, SACL, and control semantics. Emit a temporary absolute descriptor. For existing processes or threads the original implementation set only `DACL_SECURITY_INFORMATION`.

### Default object policy and propagation

Adapt `TokenDefaultDacl` for the current primary token only. `NtCompareObjects` checks identity without requiring an additional `TOKEN_QUERY` right on the caller's handle. The original setter checks authorization.

Under the original relay design, a successful update read back the effective default ACL and refreshed the propagation baseline. The current-token setter and creation or clone operations were serialized within a process. A child reset the local lock before resume. With relay off, the transform operated only on that request. A native relay installed only the creation hook and rejected an unobserved default-policy change at creation. Parent and child security-context comparisons stayed in place.

The baseline held at most 8 KiB. A successful setter with a larger ACL or a failed readback retained the setter's actual result, invalidated the baseline, and disabled subsequent relay preparation. The lock coordinated calls through the compatibility entries.

### Early initialization

The agent can run before loader initialization. It has no CRT, normal or delay imports, TLS, global constructors, `DllMain`, or extra runtime DLL. The host statically links the CRT. The early agent uses resolved Native APIs and bounded storage.

## Consequences

The current request determines adaptation. The default DACL can affect subsequent objects that use it. The existing token identity, privileges, restricting SIDs, and resource policy remain in force, as do filesystem and registry ACLs.

Tests cover descriptor fields, empty and NULL DACLs, limited access, enabled and deny-only groups, other tokens, adjust-only and query-only handles, actual MSYS setters, and the three sandbox configurations. Chain tests check the requested default after MSYS updates it.
