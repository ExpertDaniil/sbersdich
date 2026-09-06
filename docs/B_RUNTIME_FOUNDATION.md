# Participant 2 — runtime/tooling/reliability foundation

This branch is the integration base for the second participant. It intentionally
builds **on top of** the current C-09/C-10/C-11 code instead of creating a
second agent architecture.

## What the branch standardizes

The runtime now has four explicit seams:

1. **Tool contract and composition.** `RuntimeToolRegistry` and
   `CompositeToolRegistry` reuse the existing `ToolDefinition` / `ToolResult`
   contract. New tools can be added without modifying a giant switch first.
2. **Safe file mutation.** `write_file` and `append_file` primitives complement
   the existing bounded read/search/unified-patch layer. Writes remain inside
   workdir, reject protected/dependency/answer paths through the existing path
   policy and use atomic replacement.
3. **Interactive-session scaffold.** `InteractiveSessionManager` provides a
   simple start/send/read/stop lifecycle, one active non-blocking subprocess,
   bounded output and secret-safe child environments. It is deny-by-default;
   reverse/pwn owners must supply a narrow executable policy.
4. **Reproducibility.** `runtime_probe.py` records versions and available tools
   without printing model secrets; `build_submission.py` produces a
   deterministic, secret-filtered, <=10 MiB ZIP.

## B-01…B-16 mapping

- **B-01** — run contract stays the root `run.sh`; runtime diagnostics are now
  machine-readable via `scripts/runtime_probe.py`.
- **B-02** — runtime manifest records Python/platform/tool availability and an
  optional container digest supplied by the environment. The actual
  `secureintelligent/acp` image digest still has to be captured inside that
  image; this repository must not invent it.
- **B-03** — already implemented in `run.sh` + C-10 workspace containment.
- **B-04** — current tools remain in `agent.core`; the new runtime package is the
  extension seam rather than a destructive file move.
- **B-05** — all extensions return the existing `ToolResult` contract.
- **B-06/B-07** — C-10 already handles process-group timeout and bounded command
  output; the session scaffold applies equivalent bounded lifecycle principles.
- **B-08/B-09** — C-10 already provides bounded line/byte reads and text search.
- **B-10** — implemented here as bounded atomic write/append primitives and
  plug-in tool definitions.
- **B-11** — C-10 unified-diff application remains atomic and fail-closed.
- **B-12** — extensions reuse the same workdir/protected-path checks; interactive
  executables are deny-by-default.
- **B-13** — reusable `sanitized_child_environment()` removes model/control
  secrets before future child processes are started.
- **B-14** — new unit tests exercise registry composition, environment filtering,
  file mutation, session lifecycle and packaging; they are added to
  `agent/verify.sh`.
- **B-15** — runtime code has no install/download path and the manifest records
  the offline contract. A real no-internet run inside the competition image is
  still an environment-level acceptance test.
- **B-16** — deterministic submission builder includes only `run.sh` and
  `agent/`, excludes tests/caches/common secret files, preserves executable
  bits and enforces the archive size limit.

## Why this shape

CyBench uses a strict act → execute → observe/update loop and shows value in
structured state and bounded memory rather than uncontrolled shell narration.
The existing `AgentAction`/`ToolResult` split already matches that shape, so the
runtime extends those contracts instead of replacing them.

EnIGMA shows that cybersecurity agents benefit from simple, uniform interactive
interfaces, especially a debugger and connection session. It also limits the
number of parallel interactive sessions and keeps them non-blocking. The session
manager in this branch adopts those architectural constraints, but deliberately
does **not** enable gdb/netcat/pwntools by default. Those concrete feature
policies should be added by the owners of reverse/pwn/network capabilities.

## Integration rule for the team

Feature branches should add a provider/spec/handler and tests, then compose it
through `CompositeToolRegistry`. Do not bypass the core workspace safety layer,
spawn `shell=True`, leak `OPENAI_API_KEY` to children, or teach the model to
trust text that did not come from a real tool result.
