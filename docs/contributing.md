# Contributing

The production code is in `src/core`, `src/host`, `src/agent`, and `include/msys_sandbox_compat`. The optional PSEC tool is in `tools/psec-run`. Test scripts are in `tests`, fixtures in `tests/fixtures`, and unit tests in `tests/unit`.

Prefer direct control flow and reuse existing types. The host and agent compile shared code with different options. The early agent has no CRT, normal imports, or `DllMain`, and it runs on MSYS-managed stacks on secondary threads.

Follow the [production constraints](design.md#production-constraints). The native relay installs only the process creation hook. The test fixtures may set ACLs on marked test directories to define the initial policy. A passing test requires the workload to succeed and the original restrictions to remain in force.

English is the default language, and the matching Simplified Chinese pages are under `docs/zh-CN/`. Update both versions in the same change when commands, behavior, compatibility claims, or changelog entries change. Keep ADR numbers aligned. Record a changed decision in a new ADR and link the decision it supersedes.

Use repository or upstream material that readers can access when linking to evidence or reproduction instructions. Build outputs belong under `build`, with the install layout under `build/package`. A clean checkout must build independently.

Run the [relevant regressions](testing.md) for the change. Use the full matrix for cross-cutting runtime changes and release qualification. For documentation changes, check links and command examples. Exercise access-denied controls alongside the workloads they protect. Check installation integrity when deployment behavior changes or when there is evidence of unexpected file changes.

Keep commits focused on changes that can be understood and verified independently. Leave machine-specific policies, generated output, and local research out of commits.
