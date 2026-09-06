# Experimental scaffold

This package is a parallel, opt-in architecture for the competition agent. It does not replace `agent/core` on `main`.

```text
instruction
  -> classifier / task contract
  -> deterministic fast path or local-model planner
  -> Repository Distiller (tree / ranking / skeleton / symbols)
  -> hypothesis graph + trusted evidence ledger
  -> capability-gated ToolBus
  -> tool provider / persistent session
  -> environment observation
  -> deterministic verifier
  -> finish or backtrack/escalate
```

## Repository Distiller

Repository-level tasks now get a bounded structural localization layer before broad file reads. It is intentionally offline and standard-library only.

Available tools:

- `repo_tree` — compact bounded task-repository structure;
- `symbol_index` — Python AST plus lightweight JS/TS/Go/Rust/Java/Kotlin/C#/C/C++/Ruby/PHP/Shell/SQL symbols;
- `rank_relevant_files` — deterministic hybrid ranking over paths, symbols and bounded text with IDF-style weighting;
- `repo_skeleton` — signatures and locations without function bodies;
- `inspect_symbol` — one focused symbol window plus bounded repository references.

The index excludes answer/verifier paths, symlinks, VCS/cache/generated directories, limits indexed files/bytes, and automatically refreshes after workspace changes. The planner is instructed to prefer localization through these distilled views before repeatedly reading whole files.

Extension points remain deliberately small:

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

Build the deployable competition ZIP:

```bash
python3 scripts/build_scaffold_submission.py
```

See `docs/TEST_GOVNO_SCAFFOLD.md` for the team extension recipe and architecture rationale.
