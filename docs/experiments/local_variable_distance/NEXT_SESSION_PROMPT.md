# Prompt for the remote Codex session

> Historical handoff, now superseded by
> [`COREUTILS_O2_RESULTS.md`](COREUTILS_O2_RESULTS.md) and
> [`USAGE_MATCHING.md`](USAGE_MATCHING.md).

Continue the local-variable edit-distance experiment on branch
`experiment/local-variable-edit-distance`.

Read, in order:

1. `AGENTS.md`
2. `docs/experiments/local_variable_distance/REMOTE_COREUTILS_HANDOFF.md`
3. `decbench/experimental/local_variable_distance.py`
4. `tests/test_local_variable_distance.py`

Use `/home/mahaloz/.virtualenvs/decbench` and
`/home/mahaloz/bin/ghidra_12.1`. IDA 9.2 is documented in `AGENTS.md`.

First reproduce both `grep::main` demos. Then compile coreutils and run an O0
IDA+Ghidra decompile-only pass. Implement the checkpoint scorer described in
the handoff. Keep matching names blinded and distinguish matcher precision
from LVED recovery accuracy.

Start with a deterministic sample of about 100 functions. Produce:

- per-function JSONL evidence
- stage/decompiler accuracy and coverage tables
- held-out threshold evaluation with clustered bootstrap intervals
- a short list of false matches and abstentions with their address evidence

Do not scale beyond O0 until the oracle and the sampled audit agree.
