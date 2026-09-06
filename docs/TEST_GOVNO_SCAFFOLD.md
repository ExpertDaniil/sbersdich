# `test_govno`: experimental team scaffold

This branch is intentionally a playground for the whole agent, not a B-only delivery. The goal is to give the team one runnable composition root where new ideas can be added as plugins instead of editing the central loop every time.

## Design target

```text
Task
  ↓
Task classifier + artifact contract
  ↓
Deterministic fast path ──────────────┐
  ↓ stall / unknown task             │
Evidence-aware local-model planner   │
  ↓                                  │
Hypothesis graph                     │
  ↓ choose cheapest discriminating action
Capability-gated ToolBus
  ↓
Tool provider / interactive session
  ↓
Trusted observation → Evidence ledger
  ↓
Progress? ─ yes → continue
    └ no / repeated observation → branch, backtrack or escalate
  ↓ candidate result
Deterministic verifier
  ├ fail → evidence + new plan
  └ pass → success
```

The important boundary is: **the model can propose hypotheses, but it cannot create evidence**. Only `ToolResult` and validator output enter `AgentState`'s evidence ledger.

## Why this scaffold exists

The current `agent/core` already solves public profiles and has safe workspace primitives. Rewriting it would create regressions and merge conflicts. The scaffold therefore reuses existing components behind adapters and adds new extension seams around them.

`agent/scaffold/` contains:

- `contracts.py` — capability levels, plan/tool/run contracts;
- `interfaces.py` — tiny `Planner`, `ToolProvider`, `Verifier` protocols;
- `state.py` — bounded hypothesis graph, evidence ledger, stagnation/backtracking signal;
- `registry.py` — `ToolBus`, duplicate detection, mode/capability policy;
- `providers.py` — adapter for the existing `SecurityToolRegistry` plus safe `write_file`/`append_file`;
- `sessions.py` — one non-blocking persistent REPL session with bounded transcript and secret-stripped environment;
- `planner.py` — zero-token deterministic fast path plus richer local-model planner;
- `verifier.py` — current deterministic validation as a hard success gate;
- `kernel.py` — the generic loop;
- `extensions.py` — extension bundle API and an opt-in GDB example;
- `bootstrap.py` — composition root;
- `cli.py` — runnable entry point.

## Capability ladder

Tools are tagged with one of five levels:

```text
0 INSPECT      list/read/search
1 ANALYZE      static scanners / deterministic analysis
2 EXECUTE      tests and bounded commands
3 INTERACTIVE  debugger / task-server REPL sessions
4 MUTATE       patch/write/fix
```

The CLI can cap the maximum level with `--max-capability`. This makes capability escalation explicit and lets experiments compare a read-only agent against progressively more powerful tool sets.

## Interactive tools

The session manager follows three rules:

1. at most one persistent session at a time;
2. the child runs without shell interpretation and with model credentials/control variables removed;
3. output is drained in the background and only a bounded tail is returned to the model.

No interactive executable is enabled by default. `--enable-gdb` is an explicit opt-in example. Future reverse/pwn/network features should add `SessionProfile` instances rather than reimplementing process lifecycle.

## Add a feature

The preferred pattern is a provider, not a modification of `AgentKernel`:

```python
class MyProvider:
    name = "reverse-tools"

    def catalog(self, context):
        return (
            ToolSpec(
                name="decompile_function",
                description="...",
                parameters={"binary": "string", "function": "string"},
                modes=("general", "audit"),
                capability=CapabilityLevel.ANALYZE,
                provider=self.name,
            ),
        )

    def execute(self, action, context):
        ...
        return ToolResult(True, "decompiled function", data)
```

Package it as a `ScaffoldExtension`, then pass it to `build_default_application(..., extensions=(my_extension,))`. Planner-specific usage notes belong in `planner_guidance`, so feature code does not edit the global prompt.

## Run

Exact-file smoke test without model access:

```bash
python3 scripts/scaffold_smoke.py
```

Normal run:

```bash
LOCAL_AGENT_MODEL=... \
OPENAI_BASE_URL=... \
OPENAI_API_KEY=... \
LOCAL_AGENT_WORKDIR=/app \
./run_scaffold.sh 'TASK TEXT'
```

Run with explicit GDB capability:

```bash
./run_scaffold.sh --enable-gdb --max-capability 3 'Analyze the provided binary.'
```

Existing submission entry point `run.sh` is untouched. `run_scaffold.sh` is experimental and can be deployed side-by-side.

## Inspiration translated into architecture

CyBench motivates a bounded action/observation loop with explicit planning/status rather than an action-only agent. This scaffold keeps a compact state and deterministic fast path instead of replaying an unbounded transcript.

EnIGMA motivates persistent interactive tools and concise observations. The scaffold implements the lifecycle primitives, but deliberately does not hardwire benchmark-specific GDB or connection logic into the kernel.

The team can now experiment independently with:

- alternative planners or hypothesis-selection policies;
- information-gain/cost action ranking;
- LLM or deterministic context compressors;
- reverse/pwn/web/forensics provider families;
- task-local network session profiles;
- adversarial or specialized verifiers;
- automatic capability escalation;
- benchmark-specific extensions.

Those experiments should happen by replacing/adding components at the seams above, not by growing another monolithic `if/elif` loop.
