# Experimental scaffold

This package is a parallel, opt-in architecture for the competition agent. It does not replace `agent/core` on `main`.

```text
instruction
  -> classifier / task contract
  -> deterministic fast path or local-model planner
  -> hypothesis graph + trusted evidence ledger
  -> capability-gated ToolBus
  -> tool provider / persistent session
  -> environment observation
  -> deterministic verifier
  -> finish or backtrack/escalate
```

Extension points are deliberately small:

- add a `ToolProvider` for a new capability family;
- package providers/guidance in a `ScaffoldExtension`;
- replace the `Planner` for a different reasoning policy;
- replace/wrap the `Verifier` for new proof obligations.

The default application reuses the current repository's safe workspace/security tools and local OpenAI-compatible client. Model-owned `observation`, `evidence`, `facts` and `tool_result` fields are rejected: only tool and validator output enters the evidence ledger.

Quick start:

```bash
python3 scripts/scaffold_doctor.py
python3 scripts/scaffold_smoke.py
./run_scaffold.sh 'Create a file at `/app/result.txt` whose content is exactly `done`.'
```

Opt-in GDB session support, if GDB exists in the runtime:

```bash
./run_scaffold.sh --enable-gdb --max-capability 3 'Analyze the task-local binary.'
```

Build a deterministic deployable ZIP where `run_scaffold.sh` becomes submission `run.sh`:

```bash
python3 scripts/build_scaffold_submission.py
```

See `docs/TEST_GOVNO_SCAFFOLD.md` for the team extension recipe and architecture rationale.
