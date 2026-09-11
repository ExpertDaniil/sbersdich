# Second hard-benchmark run: diagnosis and follow-up

The supplied `run-20260911T193354Z` still scored **0/4**. The previous
`f2c2bb4` patch did not establish an improvement in autonomous task completion.
The earlier review of `f113f11` describes the older revision; this follow-up is
based on the new stdout, actual tool events and workspace artifacts.

## Correct accounting

Parse the complete root JSON object, not nested hypothesis `status` values.
The authoritative counters are in `metrics.model_usage`:

| Task | Requests | Tokens | Root status | Observed failure |
| --- | ---: | ---: | --- | --- |
| A02 SSRF | 10 | 64,640 | failed | Unsupported DNS-bypass claim, invalid finding schema, repeated writes |
| F05 ORDER BY | 6 | 44,385 | failed | Repeated patches retained lowercase output despite an uppercase assertion |
| R01 clock skew | 10 | 40,855 | succeeded | Chose export time instead of the requested session event |
| C03 carving | 7 | 32,052 | failed | Incorrect offset, unread format documentation, unavailable actions |
| Total | 33 | 181,932 | 0/4 externally | 467.369 seconds |

The summary adapter already provided in this branch recovers these counters and
root statuses without changing the independent verifier's verdicts:

```bash
python3 -m evaluation.scaffold_results /path/to/run-20260911T193354Z
```

## Additional root cause

A task output appeared in the semantic index as `*_schema.json`, simply because
it was JSON. The context compiler also copied it into `TRUSTED_SOURCE_WINDOWS`.
The audit and investigation rationales explicitly treated their own generated
files as an authoritative schema or corroboration. A runtime read establishes
file bytes; it does not establish truth of a model's previous claims.

## Changes

- Contract paths are taken from report output directives for audit and forensics;
  CTF parsing now handles “Store only the complete flag”. Scoped bans on changing
  tests/dependencies no longer override fix intent. Investigation routing includes
  log correlation, Kubernetes audit logs and cloud exfiltration formulations.
- Audit performs one read-only SQL scan and hands off to the model even when it
  has findings. It cannot deterministically finish merely because a scanner wrote
  a report. Specialized audit/forensics writers also enforce declared paths.
- Required outputs are excluded from both source packets and source guide cards.
  Explicit reads of a candidate carry output provenance. Generic JSON is data,
  not a schema. File handles remain stable when new files are added. Original
  `source_path` is available for report citations while tool aliases still work.
- The planner receives the exact existing audit schema, failed artifact checks,
  lowercase severity values and compact pytest assertions. Required whitespace-only
  text fails validation. Empty generic file writes remain legitimate primitives;
  tool success is not task completion.
- Referenced format documentation can enter the source packet despite the normal
  security ranking penalty for Markdown. `binary_records` computes candidate
  offsets and lengths using caller-specified magic, endian integer header and
  length field. It is bounded and read-only, rejects malformed schemas, reports
  truncated records, and never chooses the answer or decoding order itself.
- Playbooks distinguish source evidence from candidate output, require source to
  sink reasoning, and require the relevant cross-source links before selecting an
  incident timestamp. Invalid-action feedback names the rejected action and the
  available alternatives.

No hard-benchmark answers, fixed flag values or task-specific detection shortcuts
were added to runtime code. Existing independent verifiers were not modified.

## Verification and limits

Python 3.12.14 with pytest 9.1.1 in an isolated test environment:

- `scripts/check_all.sh` passed, including 265 agent tests: 264 passed and one
  Windows-specific skip. Packaging and extracted-submission tests are included.
- `evaluation/verify.sh` passed its 84 tests and evaluation fixtures.
- Ten additional independent tests cover 15 routing formulations, output paths,
  candidate provenance, stable handles, actionable model feedback, positive audit
  scan handoff, both endian formats, decoy records and malformed headers.
- A manual tool replay on a temporary copy of the supplied C03 binary located
  the configured record and recovered a 33-byte flag using the documented
  transforms. Structural completion passed and input files were unchanged.
  This is a tool capability check, not an autonomous-model or external-verifier run.

A live Qwen endpoint and Docker/ACP are unavailable here. No new autonomous 4-task
or 15-task solve rate is claimed. In particular, schema validation cannot certify
an unknown forensic conclusion, and prompt/tool improvements alone cannot prove
that a model will correct a regression or identify the proper vulnerability chain.
