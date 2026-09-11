# Byte ACI and bounded recovery

This change continues `test_govno_1` from
`f113f1138cec8a223fe10353635f137f2e1f5ef3`. It preserves the single scaffold
kernel, legacy tool registry, existing path policy, semantic aliases, and validators.

## Source and scope

EnIGMA's useful design principle is a purpose-built agent-computer interface:
tools perform the actual operations and return observable evidence, rather than
making the model simulate execution or reconstruct binary data in text.

Sources: [EnIGMA project](https://enigma-agent.com/),
[paper](https://arxiv.org/abs/2409.16165), and the linked
[SWE-agent v0.7 implementation](https://github.com/SWE-agent/SWE-agent/tree/v0.7).
This is an independent adaptation of those interface/recovery ideas. No external
agent code, benchmark answers, additional agent loop, or runtime dependency is
included. The specific bounded range transform and final verification reserve
below are local implementations, not claims about EnIGMA's exact algorithms.

## Changes

- `ctf_transform` accepts either `value + steps` or
  `path + offset + length + steps`. File mode uses the existing bounded workspace
  reader. It rejects short reads and mixed input modes, preserves the source, and
  records the exact input length and SHA-256. `reverse_bytes` reverses binary
  data; legacy `reverse` retains its UTF-8 character semantics. Tool schemas now
  document the exact XOR key fields and the initial `hex` step for textual hex.
- Audit hands off to the model when a SQL-only scan returns no findings. An
  explicitly required nonempty findings array is enforced by the existing
  artifact validator. This does not manufacture findings on clean projects.
- Evidence investigations route to forensics even when they also forbid input
  changes. Explicit JSON output paths and exact key lists become artifact rules.
  Audit/forensics get `write_file` only for declared artifact paths; source
  writes remain rejected. The forensics playbook distinguishes collector clock
  correction from later correlated request/export timestamps.
- `security_scan` returns bounded actual findings, not only a count. A small
  finite-string analysis recognizes direct local allowlist guards and safe
  constant fallbacks for SQL tokens. Unknown control flow, calls, mutations,
  unguarded branches and subsequent untrusted reassignment retain taint. The
  scanner still has limited coverage and is not a general proof of security.
- Final fix validation scans the current workspace after project tests. A
  pre-edit scan can neither falsely block a repaired candidate nor certify a
  subsequently vulnerable one. Findings appear in validation feedback.
- Invalid model responses receive bounded corrective retries, with the error
  available in the next planning context. Existing hypothesis IDs select the
  original nodes; using the current ID cannot fake a backtrack.
- Context is compacted as a JSON object rather than sliced into invalid JSON.
  Required tool schemas, artifact rules and recovery feedback are retained.
  The state also retains the latest bounded observation per path, and evidence
  IDs remain unique after ledger eviction.
- Planning reserves 10% of the task deadline, capped at 10 seconds, for final
  verification. After planner failure or step exhaustion, a result written since
  the previous check gets one final check within the remaining validation/time
  budgets. Wrong content, missing outputs and undeclared mutations still fail.
  Explicit aborts are not converted into success. No result is synthesized.

## Validation and limitations

The baseline used Python 3.12.14: `agent/verify.sh` passed 238 tests with seven
environment skips; `scripts/check_all.sh` also passed. The development environment
initially lacked pytest. Installing pytest in a separate test virtualenv enables
the real project-test and extracted-submission integration checks without changing
submission dependencies. Docker/ACP and a configured live model endpoint are not
available in this environment.

Final checks on Python 3.12.14 with pytest 9.1.1 in that isolated virtualenv:
`agent/verify.sh` and `scripts/check_all.sh` passed all 255 agent tests (only
the Windows 8.3 regression is skipped), including the extracted-ZIP real-pytest
test. `evaluation/verify.sh` passed 84 tests and its portability, CTF and context
efficiency suites. A direct run of the public service fixtures cannot complete
here: their project tests require the ACP service dependencies (first missing
module: httpx); this is not recorded as a passed public-verifier run.

New independent regressions cover binary ranges at several offsets, incomplete
reads, protected paths, exact artifacts, nonempty audit output, JSON investigation
contracts, current-source scan validation, safe and unsafe allowlists, planner
retries, final recovery checks, unique evidence IDs, and valid compacted JSON.
They use generated local fixtures, not hard-benchmark expected answers.

Run the established gates:

```bash
./agent/verify.sh
./scripts/check_all.sh
./evaluation/verify.sh
```

Passing these tests does not imply a new hard-benchmark solve rate. Repeat the
same external benchmark with the same model/settings after pulling this branch.
The external verifier remains the authority on task correctness, including
semantic JSON conclusions and exact CTF answers. Input rejection versus safe
fallback for malformed sort values must be assessed against the benchmark's
actual specification; this patch does not alter hidden verifiers.

## Recovering external harness metrics

Some external runners read a legacy metrics shape or a nested hypothesis status.
The full scaffold stdout contains the authoritative root status and
`metrics.model_usage`. This development-only adapter recovers those fields while
preserving every original verifier verdict and leaving the original files alone:

```bash
python3 -m evaluation.scaffold_results /path/to/results/run-TIMESTAMP
```

Missing or malformed usage is an error rather than a silent zero. The adapter is
excluded from the submission ZIP along with the rest of `evaluation/`.
