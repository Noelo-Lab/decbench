# PDB first-PC source location convergence

Status: unsubmitted experimental follow-up to PR #103 at
`ad8ceafcbbefb3c9efa795a9bc443968e0b165e2`. This expands diagnostic oracle
coverage, not decompiler quality or official C++ scores. No producer code changes.

## Measured failure and owner

The frozen qualification pilot has 250 requests across 45 linked images at
dataset revision `07dd95dbe6214b8a78fc1e4a55961ab515986489`, sample SHA256
`f432c528e3071efa60fdaecc132aafa8c351e386bf7203d252e2875d6de02620`.
Nineteen Windows requests lacked a singular native file/line hint. Inspection of
their original matching PDBs found seventeen with distinct C13 source rows at
one first PC and two with no line rows inside the procedure range. An independent
LLVM PDB line dump also retains duplicate-PC line records. This is native
provenance ambiguity, not permission to choose one line or infer it by name.

The PDB owner now retains the complete deduplicated, sorted first-PC candidate
set. Its legacy singular `source_file`/`source_line` behavior is unchanged.
The experimental source-CFG join requires every retained candidate to resolve
uniquely, within its proven TU, to the same exact parser definition object.
Missing, ambiguous or conflicting candidates reject the join. Template, qualified
name, parser, ICF and source-unit gates still apply after convergence. No nearest
line, basename or same-name fallback is introduced.

`cpp-ged-origin-v3-diagnostic` distinguishes the changed diagnostic contract.
The default GED/type/byte metrics, metric caches and Union remain unchanged.

## Frozen replay

All four tools reuse their saved output and the same 250 requested addresses.
No producer or corpus program is executed. Both evaluator versions freshly
parse the same source inputs with metric caches disabled and Rust-Joern pinned
to `9fd97f50885202596b125ebd2504e64910874bcb`. The proposed Rust-Joern syntax
candidate is not adopted by this experiment.

| Tool | Source eligible before/after | Paired before/after | Distance zero before/after |
| --- | ---: | ---: | ---: |
| Fission | 54 / 56 | 54 / 56 | 18 / 19 |
| Kuna 1.808 | 54 / 56 | 53 / 55 | 21 / 23 |
| angr | 54 / 56 | 34 / 36 | 14 / 16 |
| Ghidra | 54 / 56 | 50 / 52 | 19 / 21 |

The two newly connected native definitions are Windows OpenCC O2
`opencc::UTF8Util::IdeographicDescriptionOperatorArity` (header lines 124/125)
and Windows Snappy O2-noinline `snappy::UNALIGNED_LOAD64` (lines 145/149).
Each pair resolves to one definition in its own proven TU. These rows were not
resampled and their raw producer texts and binary hashes are unchanged.

Every previously matched source definition digest and every previous measured
GED result is identical. The complete source/ABI type profiles are identical
excluding computation time: 26 eligible functions per tool, perfect Fission 0,
Kuna 1, angr 0, Ghidra 0. No byte-match or ranking claim is made.

Of the seventeen multi-location requests, two now match, eight reach the existing
unsupported-template boundary, one fails qualified-name correspondence, one has
a parser failure and five remain ambiguous. The two procedures without line
records still abstain. The original twenty-seven missing-TU requests also remain
unresolved: freshly rebuilt TUs cannot become evidence for older binary identities.

A second fresh candidate replay is identical for all 45 cells and all four tools
after removing only `computation_time`. The compact population/evidence summary
is [retained here](cpp-first-pc-population.json); full source/CFG evidence, native
line audits, hashes and comparison scripts remain in local artifacts.

## Validation and boundaries

* Eleven new regressions exercise real C13 row transport, native candidate
  transport, convergence, conflicting/unmapped/zero-line cases, overload ambiguity,
  TU boundaries and retained template/name gates.
* Focused workflow locally: 327 passed, 5 platform-specific skips; selected
  Black/Ruff and ten owner mypy checks pass.
* Full baseline: 997 passed / 19 failed / 24 errors / 28 skipped.
* Full candidate: 1,008 passed / 19 failed / 24 errors / 28 skipped.
  All 43 failure/error identities are identical; no new identity remains.
  A separate PDB-owner mypy audit retains its same eighteen pre-existing errors;
  the focused mypy lane does not claim the entire repository is type-clean.
* No exact-head remote DecBench CI has run for this unsubmitted patch. Human
  review under `docs/agents.md` is required before committing/submitting it.

Multiple line rows proving one definition do not establish instantiated template
semantics, implicit lifetime/exception effects, source/ABI recompilation parity
or full PDB support. The corpus remains `qualified=false`, `scoring_ready=false`.

Artifacts: Fission `benchmark/artifacts/cpp-evidence-recovery/2026-10-22/`.
The same frozen `qualification-v2/` files are now available on HF main as an
additive packaging promotion, while the immutable original dataset revision and
legacy corpus are preserved. That packaging operation is separate from this
evaluator change and does not alter any bytes used for this replay.
