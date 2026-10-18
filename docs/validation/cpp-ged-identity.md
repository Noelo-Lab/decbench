# Experimental C++ GED identity validation

Base: `fbb977571ef7737d982849351fa6f7c17aeb4bbb` (PR #103).

See [metric contracts](../metrics.md#experimental-c-ged-connection-diagnostics).

Frozen dataset: `sjkim1127/decbench-cpp-qualification` revision
`07dd95dbe6214b8a78fc1e4a55961ab515986489`.
Frozen sample SHA256: `f432c528e3071efa60fdaecc132aafa8c351e386bf7203d252e2875d6de02620`.
250 entries / 45 binary cells: Linux 108, Windows 97, macOS 45.
Frozen Fission and Kuna 1.808 output are re-ingested; these are **not fresh
producer runs** and are not a comparison against current/latest decompilers.
The corpus retains its staging/qualification limitations.

## Measurements

The legacy combined/name-keyed decompiled CFG path connected only **2/250 for
each tool** (`baseline.json`). Emitted identifiers and transport/oracle names
usually differ. This was a connection/grammar/identity failure, not a quality
measurement.

The first exact-identity diagnostic had 21 source CFGs and 114 missing TU
connections. Resolving relative origins via native compilation directories and
exact generated-CU bindings from recorded object/source commands increased
source coverage to **48/250**, with **27** missing TU connections remaining.
These intermediate numbers measure evaluator coverage, not decompiler progress.

| Final diagnostic | Fission frozen output | Kuna 1.808 frozen output |
| --- | ---: | ---: |
| Requested functions | 250 | 250 |
| Producer-record CFG connected | 249 | 246 |
| Common source CFG population | 48 | 48 |
| Source/producer CFG paired, GED measured | 48 | 47 |
| GED distance zero (diagnostic) | 18 | 20 |
| Mean distance, tool-specific measured population | 56.3125 | 48.9574 |
| Median distance, tool-specific measured population | 7.5 | 6.0 |

The common 47 paired entries have 18 and 20 distance-zero results respectively.
Kuna's remaining source-eligible output fails Joern declaration recovery; it is a
**per-output parser-health failure**, not a new oracle exclusion. Full evidence is
in `producer-cfg-failures-on-eligible-source.json`. No full-corpus C++ perfect
percentage, Union, official ranking or Fission quality improvement is inferred.

| Platform | Requested | Common source eligible | Fission paired | Kuna paired |
| --- | ---: | ---: | ---: | ---: |
| linux | 108 | 24 | 24 | 24 |
| windows | 97 | 8 | 8 | 8 |
| macos | 45 | 16 | 16 | 15 |

## Source population and exclusions

All 250 entries remain in the request plan. The source population is identical
between tools by exact `(cell, address)`, including the same 202 exclusions.

| Source status | Count |
| --- | ---: |
| Multiple concrete native records at entry | 16 |
| Defining logical file absent from retained source origins | 42 |
| Unproven local/anonymous native scope | 9 |
| Source CFG admitted | 48 |
| Selected definition/scope syntax not proven | 4 |
| Template specialization policy absent | 46 |
| Joern did not produce exactly one real definition (zero or multiple) | 16 |
| Origin exists but no containing definition | 7 |
| Explicit source parser diagnostics | 7 |
| Native/source qualified names disagree | 9 |
| No exact TU connection | 27 |
| Native source file/line unavailable | 19 |

Nine name/scope-disagreement candidates are **rejected**, rather than credited
by a matching leaf name or a larger/nearby CFG. Duplicate native entries, source
ambiguity and unsupported specialization do not borrow another function's CFG.
`rejected-name-mismatches.json` records the rejected candidates.

## Identity audit and its limits

Every admitted row retains its native entry/DIE or PDB identity, full native and
source names, TU evidence, original file/line, preprocessed physical span and
parser scope. Compilation-database aliases retain exact command and database
hashes. Relative paths use the recorded native directory, never evaluator cwd.

An independent original-source-bundle check found 35 qualified-name+line matches,
11 leaf+line matches with raw-source parser scope recovery limitations, and two
macro-decorated class declarations that the raw-source parser could not index.
The 13 supplemental original declaration contexts were read directly; the two
macro cases are `Status::ok` and `DictEntry::GetDefault`. No accepted identity
contradiction was observed in this bounded inspection. The machine audit does
**not** establish fully automatic 250-function freedom from mismatches: 202 rows
abstain, raw-source scope recovery has limits, and build/link provenance remains
asserted rather than independently qualified. See `original-audit-final.json`
and `original-manual-context.txt`.

## Determinism and inputs

Two fresh source-AST/source-CFG/producer-CFG passes per cell, with metric caches
disabled, produced byte-identical complete JSON for **45/45 cells**. An immutable
native index is shared between the two passes and validated by binary/database
hashes. Raw outputs are read again; no producer is invoked. The earlier full
native-reader two-process replay was also identical for 45 cells before the TU
transport extension. These scopes are distinct.

the retained input manifest binds 768 input files (500 raw producer JSON files,
45 original and stripped images, native debug artifacts, source archives,
compilation metadata and the sample). Each original binary hash agrees with the
frozen sample. the retained code manifest binds evaluator/test/workflow sources.

## Validation

- New GED regressions: **33 passed**, including real DWARF 4/5 and PDB fixtures,
  actual saved-temp compiler inputs at O0/O2, relative and MSVC/GCC markers,
  overloads, exact qualified scope, ICF ambiguity, wrong-TU/source disagreement,
  one-record parse isolation, fixed population, stale-index rejection and CLI.
- Focused workflow's pytest lane locally: **202 passed / 5 platform skips**.
- Full repository baseline: **874 passed / 19 failed / 28 skipped / 24 errors**.
- Full candidate: **907 passed / 19 failed / 28 skipped / 24 errors**.
- The **43 pre-existing failure/error identities are identical**, no new or
  removed identity. See `pytest-regression-comparison.json` and both JUnit logs.
- New owner mypy checks and scoped Black/Ruff checks pass.
- No remote CI run is claimed for this unsubmitted delta. The workflow is updated
  for the new regressions and owners. The pinned native parser remains
  `9fd97f50885202596b125ebd2504e64910874bcb`.
- No guest corpus binary was executed, no native producer was rerun, and no
  website/snapshot/Hugging Face/leaderboard publication was performed.

## Bounds and next work

Strict definition-only explicit CFG parsing does not qualify full-TU callee
context, template specialization, implicit object lifetime or exception edges.
Generic evaluator/infrastructure errors propagate; only explicit parser error
diagnostics become parser-health failures, and nonfinite GED is an evaluator
failure. Existing GED arithmetic is reused without a new default metric.

The next source-coverage blockers are missing TU evidence (27, Windows), native
file/line evidence (19, Windows), absent retained origins (42), and template
specialization policy (46). Collect/qualify those artifacts or policy separately;
do not shrink or replace the frozen 250 requests to improve a score.


Full reports, inputs/code hashes, producer/source audits and reproduction drivers
are retained locally in Fission `benchmark/artifacts/cpp-ged/2026-10-18/`.
This note is diagnostic evidence; it neither adopts an official C++ GED policy
nor marks the corpus scoring-ready. Remote CI must run after approved submission.
