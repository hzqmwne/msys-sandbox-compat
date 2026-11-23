# ADR-0007 — Ship the compatibility shim separately from the PSEC test tool

Status: Accepted
Date: 2026-10-20

Related: [ADR-0001](0001-suspended-msys-preparation.md), [ADR-0005](0005-restricted-token-context.md), [ADR-0006](0006-opt-in-native-relay.md).

## Context

Production use starts in the restricted environment supplied by an external launcher. `psec-run` creates a PSEC for testing from a normal host. Installing both together made it unclear which binaries production needed. The shared host and agent implementation also needed its own source directory.

## Decision

The default build produces the development EXE and DLL and the standalone `msys-sandbox-compat-shim.exe`. The shim embeds the validated DLL as a PE resource. Installation ships the shim, documentation, and license notices. Building tools or tests explicitly adds `psec-run`, and the test fixtures have separate sources and outputs. Starting with v0.1.0, the release build explicitly enables tools and ships `psec-run.exe` as a separate executable.

Core holds shared recognition, preparation, and token code. The host and CRT-free agent build it under their respective constraints. Production runs at the locations and permissions allowed by the existing policy.

## Consequences

An existing sandbox launcher deploys one executable. The repository demo requires the tool build and the integration suites require the test build. The embedded resource is regenerated from the validated DLL, and the single-file test runs a renamed shim from an isolated directory.
