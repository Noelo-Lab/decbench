# C++ evaluator review follow-up

Local proposal, 2026-10-18, against [PR #103](https://github.com/Noelo-Lab/decbench/pull/103) head `cfcc485e964a9298d08714816cd4839809be3d6b`. This is benchmark correctness work, not a Fission speed/quality patch or an official C++ policy. [Compact evidence](cpp-review-fixes.json).

## Changes

- Restrict function-level oracle abstention to explicit `UnsupportedType` and `PdbFormatError` during oracle preparation. Run recovery scoring outside that boundary. Unexpected evaluator/parser `ValueError` propagates instead of silently reducing the eligible population; source contexts still close on failures.
- Add native `PdbFormatError(ValueError)` for recognized unsupported/invalid PDB/CodeView checks. AST comparison proves the reader changes only the exception class/declaration and explicit raise names; parser algorithms/messages and existing ValueError-compatible callers remain unchanged. This avoids converting intentional native format exclusions into arbitrary evaluator-failure exclusions.
- Require scoped display names to be nonempty and unique among all function variables, at both the Fission adapter and shared matching owner. Duplicate names gain no scoped PCs. Keep direct variable PCs primary, independent stack/ABI evidence intact, and the legacy whole-line mapping contract unchanged. Stable binding-ID transport remains future work.
- Resolve configured/PATH Fission executable paths before changing the child working directory. Real fixture process tests cover relative paths, spaces, changed cwd and version/decompilation calls.
- State the actual normal `tree-sitter-cpp` runtime dependency. Do not invent cross-format virtual-base equivalence; native locator equality remains an experimental policy limit.
- Bump `type_match` cache 23 ->24 and experimental evaluator cache 2 ->3. Keep `cpp-types-v2-proposal`, the type-comparison rules, default metrics and Union unchanged. Include the new tests in the existing focused Ubuntu workflow.

## Validation

The ten new regression cases fail on the original implementation and pass after the change. Existing focused lane: baseline **156 passed /5 skipped**, candidate **166 passed /5 skipped**. Native Mach-O/DWARF/dSYM and real CodeView/PDB compiler fixtures pass. Off-host optimized ELF, Thumb and ELF ICF cases still skip honestly on this Mac. The new workflow includes all new cases; this is not a claim of fresh remote Ubuntu success.

Full local repository: baseline **863 passed /20 failed /28 skipped /24 errors**; candidate **873 passed /20 failed /28 skipped /24 errors**. All 44 failure/error identities agree; no new identity. These include existing eval-kit/host-format, backend and content failures, listed in compact evidence. The full repository is not green. Initial collection also lacked the declared mistune and pinned rust-joern packages; install them in the isolated environment and rerun both sides. Keep the initial collection log.

Scoped Black/Ruff and four C++ policy mypy owners pass; diff check passes. Shared Ruff still reports the identical pre-existing `SIM105` in `type_match.py:557`; do not claim whole-repository lint clean. Pinned Rust-Joern remains `9fd97f50885202596b125ebd2504e64910874bcb`. The PDB exception-only AST check is retained.

## Frozen qualification replay

Dataset [qualification-v2 revision](https://huggingface.co/datasets/sjkim1127/decbench-cpp-qualification/tree/07dd95dbe6214b8a78fc1e4a55961ab515986489); [dataset](https://huggingface.co/datasets/sjkim1127/decbench-cpp-qualification); [earlier raw corpus](https://huggingface.co/datasets/sjkim1127/decbench-cpp-raw-corpus).

Re-ingest the same frozen Fission and Kuna outputs, **250 per tool across 45 cells**, then evaluate source and ABI views independently with score caches disabled. Producers are not rerun; these are the earlier frozen outputs, not current Fission/main or latest Kuna results. Source/debug artifacts stay exclusively on the evaluator side. All cell report fields, oracle exclusions, matching/type decisions and legacy PDB diagnostic outputs agree between baseline and candidate, excluding only `tools.*.legacy_pdb_abi_diagnostic.computation_time_seconds`. The first strict comparison exposed legacy timing differences. All 36 raw differences across 18 Windows cells are exactly those duration fields; raw reports, the initial failed comparator log and the correction are retained. No score or evidence field is excluded. Shared eligible population remains 26/250; Fission source/ABI perfect 0/26, fixed Kuna 1.808 source/ABI perfect 1/26. This is supported-subset evidence, not a complete C++ score or ranking. No denominator is silently reduced on an unexpected evaluator fault.

Verified 572 input/debug/producer artifact hashes, including all 500 raw producer records. Frozen Fission output has no ambiguous or empty variable display names, so the new rejection path has zero affected records in this population. Source/test file hashes and every full per-cell output are retained locally. The initial sequential evaluator launcher was replaced with two spawn workers plus one disjoint macOS-tail worker; complete checkpoints were preserved. No performance claim follows from this validation orchestration.

## Submission and remaining decisions

PR #103 stays a dependent draft on open #91. Upstream main advanced to `ae070b885b4e005ed37510a2c3445af6284dc2b9` via an unrelated GED change; this follow-up is based on the exact current PR head, without bundling that upstream change. The existing upstream run 38410600522 is `action_required`. A fresh exact-head CI run is required after approval/push. No comment, push, PR update, website/snapshot/CHANGELOG or dataset publication is performed by this local preparation.

DecBench `docs/agents.md` requires human ownership/review of the complete contribution before submission. The earlier approval covered the original #103 patch, not this new delta. Review the complete follow-up patch, report and proposed PR update before approving submission. Official C++ type policy, cross-format virtual-base semantics, expanded oracle eligibility and stable producer binding IDs remain open. Fission performance work stays stopped and preserved separately.

## Reproduction

Use Python 3.12 and the declared development dependencies, with pinned rust-joern as in `.github/workflows/cpp-policy.yml`. Run that focused pytest/Black/Ruff/mypy lane, `pytest --no-cov` on both exact source revisions, then compare failure identities. `tests/test_cpp_review_contracts.py` contains the new standalone regressions. Full replay drivers, immutable source/input hashes, per-cell reports, logs and the complete proposed patch are retained under Fission `benchmark/artifacts/cpp-type-policy/2026-10-18-review-fixes/`. No canonical results tree or published score is rewritten.
