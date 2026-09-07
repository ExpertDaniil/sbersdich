# Experimental scaffold

This package is a parallel, opt-in architecture for the competition agent. It does not replace `agent/core` on `main`.

```text
instruction
  -> classifier / task contract
  -> deterministic fast path or local-model planner
  -> Repository Distiller (tree / ranking / skeleton / symbols)
  -> Cyber ACI (search / bounded view / checked edit / proof check)
  -> hypothesis graph + trusted evidence ledger
  -> capability-gated ToolBus
  -> tool provider / persistent session
  -> environment observation
  -> deterministic verifier
  -> finish or backtrack/escalate
```

## Repository Distiller

Repository-level tasks get a bounded structural localization layer before broad file reads. It is intentionally offline and standard-library only.

Available tools:

- `repo_tree` — compact bounded task-repository structure;
- `symbol_index` — Python AST plus lightweight JS/TS/Go/Rust/Java/Kotlin/C#/C/C++/Ruby/PHP/Shell/SQL symbols;
- `rank_relevant_files` — deterministic hybrid ranking over paths, symbols and bounded text; security tasks add static risk priors without turning those priors into trusted findings;
- `repo_skeleton` — signatures and locations without function bodies;
- `inspect_symbol` — one focused symbol window plus bounded repository references.

The index excludes answer/verifier paths, symlinks, VCS/cache/generated directories, limits indexed files/bytes, and automatically refreshes after workspace changes. The planner is instructed to prefer localization through these distilled views before repeatedly reading whole files.

Security-aware ranking lives in `security_relevance.py` rather than the generic distiller. The separation is deliberate: ordinary repository queries retain generic lexical/structural ranking, while security/audit/fix instructions can additionally prioritize source files that contain static risk signals such as attacker-controlled interpolation into SQL, dangerous execution sinks, unsafe deserialization, or disabled verification. These are ranking hints only; evidence still comes from tools and validators.

The public-fixture regression benchmark can be run against the official competition repository:

```bash
python3 scripts/benchmark_distiller.py \
  --public-root /path/to/UniversalAgenticCompetitionPublic \
  --min-top1-rate 1.0 \
  --min-top3-rate 1.0 \
  --min-top5-rate 1.0 \
  --min-context-reduction 0.90
```

The competition-contract CI runs this benchmark before the Harbor-style upload smoke tests, so a localization regression fails the branch even when the old deterministic public-task fast path still succeeds.

## Cyber ACI

The default scaffold now exposes a compact Agent-Computer Interface instead of making the model depend on shell-like, high-entropy interactions. Repository work should normally follow:

```text
search_surface
  -> view_window
  -> checked_edit
  -> run_check
```

- `search_surface` tokenizes a natural-language query into a few high-information terms, merges bounded workspace matches, and reranks them using the shared security-aware Repository Distiller. Only the top 12 locations are returned by default; lower-ranked overflow is summarized as a count.
- `view_window` returns at most 120 numbered lines plus a full-file SHA-256. The digest is an edit capability token: it proves which exact file version the model inspected.
- `checked_edit` replaces one inclusive line range only when the SHA-256 still matches. Stale views fail closed. Python, JSON and TOML candidates are parsed before the atomic write, and rejected edits never touch the workspace. A successful edit automatically reopens a small post-edit window and returns a bounded unified diff.
- `run_check` exposes structured proof profiles (`python-syntax`, `pytest`, `git-diff`, `git-status`) on top of the existing command allowlist rather than arbitrary shell execution.

The ACI is task-policy aware. `audit` and `forensics` receive read/search only; `fix` and `general` can additionally execute checks and mutate. ToolBus still applies the global capability ladder, so an INSPECT-only budget exposes only `view_window`. The ACI and Repository Distiller share one cached index in the production composition root rather than rescanning the repository independently.

Legacy `read_file`, `search_text`, `apply_patch` and `run_command` remain available as fallback interfaces for operations the compact ACI cannot express. The planner prompt explicitly prefers the compact protocol first.

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
