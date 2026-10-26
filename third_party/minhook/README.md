# MinHook core provenance

Upstream: https://github.com/TsudaKageyu/minhook
Version: v1.3.4
Revision: c3fcafdc10146beb5919319d0683e44e3c30d537
License: ../LICENSE.minhook (includes the HDE copyright notices).

hde/ contains unmodified src/hde/{hde64.c,hde64.h,table64.h,pstdint.h}.
MSVC compiles hde64.c as C++ under the same no-CRT settings as its caller.

../../src/core/hook_minhook.cpp adapts upstream src/trampoline.c, preserving its
BSD notice and branch/call/jump construction approach. The public interface is
../../include/msys_sandbox_compat/inline_hook.h; it contains no MinHook types.
Only this backend and the HDE source are selected in CMake, so a future backend
can replace them without coupling the process installer to either library.

Changes from upstream trampoline.c: AMD64 only; separate readable local bytes
from source/destination VAs; bounded padded decode; checked RIP/entry ranges;
no allocator, thread management, relay allocation or patch-above path; caller
owns output storage; explicit errors; reject internal branches over expansions
and into non-instruction boundaries. The patch writes five bytes at the public
entry, and the nearby agent provides the handler and 64-byte trampoline slots.

Unknown/truncated instructions, out-of-range relative addresses and unsupported
internal branches fail planning. Address-size overrides on RIP operands,
operand-size overrides on branches, XBEGIN and relocated INT3 are rejected.
The installer supports suspended new processes only: its caller terminates the
target on failure; there is no cross-entry rollback or online unhook manager.
