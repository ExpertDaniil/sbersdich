# Participant 2 runtime/tooling foundation

This package is the extension seam for **B-01…B-16**. It does not replace the
current C-10 `agent.core.workspace` or `SecurityToolRegistry`; it wraps and
extends them through the same `AgentAction` / `ToolDefinition` / `ToolResult`
contracts.

## Add a new tool

1. Create a `ToolDefinition`.
2. Wrap it in `RuntimeToolSpec` with allowed modes and `CapabilityLevel`.
3. Register a handler in `RuntimeToolRegistry`.
4. Compose it with the current registry through `CompositeToolRegistry`.
5. Add a bounded test before wiring it into `AgentLoop`.

No feature should bypass workspace containment, model-secret stripping, output
limits or the final deterministic validator.

## Interactive features

`InteractiveSessionManager` is intentionally deny-by-default. A reverse/pwn
feature owner supplies a narrow argv policy for a concrete interface (for
example a gdb wrapper). The manager keeps only one parallel session, never uses
a shell, strips model credentials from the child environment and bounds the
transcript.

## Submission

`python3 scripts/build_submission.py` creates a deterministic archive containing
only `run.sh` and the `agent/` package, excluding tests, caches and common secret
file types.
