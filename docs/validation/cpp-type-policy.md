# C++ object policy and Fission line provenance — local validation

Status: experimental upstream proposal; no official policy, Union or ranking update.

## Population and producer scope

Frozen qualification-v2 revision `07dd95dbe6214b8a78fc1e4a55961ab515986489`; 250 address-guided stripped inputs:
Linux 108, Windows 97, macOS 45, spanning 45 project/platform/optimization cells.
The corpus still lacks complete original-source/command qualification gates.
Population SHA256 `f432c528e3071efa60fdaecc132aafa8c351e386bf7203d252e2875d6de02620`. Original debug files stay with the
evaluator; producers receive only isolated stripped images and entry addresses.

Fission baseline source `52c81dd15e9b2c9efa8cd29f4b5153f1a2690f45` was built in a clean worktree.
Both baseline and final candidate generated 250 nonempty functions without output reuse.
Final producer binary SHA256 `20b4ccf68b5562084953fb4441b0e84dea25c1151b1dc1b325d05e36505571d0`. Kuna 1.808 outputs are
reused from the earlier frozen 250-function run; Kuna was not freshly generated here.

## Fission transport results

* **105/250 functions, 237 scoped NIR definition-line mappings**: Linux 57,
  Windows 24, macOS 24 functions. All 237 PCs passed exact native instruction checks.
* **0 changed NIR texts or direct variable lists** across the same-source 250 baseline/candidate pairs.
* 144 functions carried direct variable PCs; all 9,482 variable/PC pairs survived validation.
  Pairs are counted per variable, not distinct instruction addresses.
* Linux Snappy O0, Windows Snappy O2 and macOS Ninja O2 anchors were generated twice
  using the final binary. Code, variables and scoped line maps were deterministic;
  Linux/macOS yielded 8/2 maps, the Windows anchor conservatively yielded none.
* Maps are partial result-definition origins, not full RHS/call/load/branch lineage.
  Phi/input/cloned/repeated-definition/partial/unproved cases remain unmapped.
* Text equality and compiler/debug probes are not execution parity or a decompiler
  semantic/readability improvement. No binary or recovered function was executed.

## Type policy results

Both tools and both views have the same **26/250 eligible functions**, including
**21 functions with complete object graphs**. v1 had 5 eligible scalar functions;
that difference is broader measurement coverage, not a decompiler quality delta.

| Producer | Source perfect | ABI perfect | Source mean | ABI mean |
| --- | ---: | ---: | ---: | ---: |
| Fission candidate | 0/26 | 0/26 | 0.009615 | 0.048077 |
| Kuna 1.808 (frozen output) | 1/26 | 1/26 | 0.096154 | 0.096154 |

An opaque object spelling cannot earn name/size-only credit. Complete fields,
offsets, pointee graphs and base relations are compared after type-blind variable
matching. Source and ABI remain distinct views. Producer missingness is a miss;
unsupported oracle data excludes the whole function identically for both tools.
These rates do not represent the 224 unsupported functions or an official ranking.

Legacy PDB ABI diagnostic controls remain unchanged: Fission 19/97 eligible,
0 perfect, mean 0.013158; Kuna 32/97 eligible, 0 perfect, mean 0.015625.
The default public PDB/type policy is not replaced by this experimental metric.

### Exclusions (224 functions)

* 16: DWARF function missing or entry identity ambiguous
* 5: oracle variable correspondence unavailable
* 31: anonymous object identity unsupported
* 10: unsupported DWARF graph DW_TAG_subroutine_type
* 10: incomplete DWARF object definition
* 1: inline variable identity policy unsupported
* 67: partial/composite/computed DWARF location
* 64: PDB identity/storage/formal classification incomplete
* 1: no observable variable ground truth
* 11: ambiguous/incomplete CodeView forward record
* 8: CodeView vptr physical offset unavailable

Computed/split locations, hidden/formal/storage ambiguities, anonymous/forward
objects, function/member pointers, incomplete native vptr positions and inline
identity remain explicit bounds. Virtual-base locators are preserved, never
converted to offset zero; cross-debug-format equivalence is not inferred.

## Formal validation

* Fission: 1,328 nextest tests passed, 1 skipped; pcode/decompiler/CLI checks,
  release build, workspace fmt and owner-boundary scan passed.
* DecBench C++ CI lane locally: 156 passed, 5 platform-specific tests skipped.
  New graph tests compile real DWARF and CodeView/PDB fixtures, exercise ordinary
  bases/fields, opaque/incomplete rejection, pointer cycles and missing-recovery
  population invariance. Pure CodeView fixtures cover virtual locators/bitfields.
* New policy mypy: 4 files clean. New owner Black/Ruff checks passed.
* Full local repository pytest baseline: 806 passed, 23 failed, 26 skipped, 24
  errors. Final run: 864 passed, 19 failed,
  28 skipped, 24 errors, with no new failure identities. Two overload/cache fixture
  failures were fixed; two GNU/ELF ICF tests now skip honestly on this Mac.
  Remaining failures include host compiler/object-format assumptions, site-content
  expectations, evalkit ELF fixtures and backend/source-native tests. They are
  recorded, not reported as full repository success.
* Full-repository style/type checks remain non-green: Ruff 20 findings, Black
  11 files needing format, and mypy 84 errors in 25 files. Scoped new policy
  checks are clean; these repository-wide findings are retained in the logs.
* The new Ubuntu workflow includes all relevant identity/provenance tests and
  compiles real ELF/PDB fixtures. Remote CI has not run before submission.
  Rust-Joern (existing CFG dependency) is pinned to
  `9fd97f50885202596b125ebd2504e64910874bcb` for reproducibility.

## Reproduction and evidence

`cpp-type-policy-population.json` records immutable selection and input/debug
hashes. `cpp-type-policy-summary.json` records code hashes and aggregate decisions.
Use `scripts/evaluate_cpp_type_policy.py` on canonical `DecompilationResult` JSON
with an explicit original debug image, requested-function list, view and data model.
No score/decompilation cache is used. Source units, if supplied, are evaluator-only.

Full native outputs, paired baseline/candidate generation, cell scores, exclusions,
logs and repeated probes are retained locally under
`benchmark/artifacts/cpp-type-policy/2026-10-13/` in the Fission workspace.
The code is based on DecBench main `14e14b87429043aa06f64e067847ac0a925e41a6`
and includes the still-open #91 prerequisites. Submit as a dependent draft and
remove the prerequisite diff once #91 lands. Human review is required by DecBench
AGENTS.md before submission; no leaderboard/site publication is requested.

## Correctness review follow-up (base 9f50ebf)

Three review findings are fixed locally and remain subject to submission review:

* The C++ type evaluator rejects multiple producer records at one native address
  after requested-address filtering and before oracle preparation. Missing output
  stays empty recovery; extra records outside the plan do not expand the population.
* The shared parser selects an error-free C++ AST when C parsing fails, including
  ordinary `int&`/`int&&` parameter declarations without special function names.
  Valid C inputs retain their C grammar.
* Nominal object indirections tokenize `&&`, `&` and `*`. An object rvalue reference
  has one `rref` layer and one pointer layer in ABI projection. Invalid nested
  references abstain; ILP32 object-layout requirements are unchanged.

C++ type cache generation is 4; the shared-parser change bumps legacy type-match
cache generation from 24 to 25. No default C++ metric or policy adoption is added.

Pre-fix reproduction: 14 failed / 6 passed. Current focused workflow locally:
268 passed / 5 platform skips, with scoped Black/Ruff and C++ owner mypy clean.
Full baseline: 927 passed / 19 failed / 28 skipped / 24 errors. Candidate:
949 passed / 19 failed / 28 skipped / 24 errors. All 43 existing failure/error
identities are unchanged. Real DWARF and clang-cl/PDB fixtures compare recovered
rvalue-reference object graphs in source and ABI views without running them;
these graph fixtures do not qualify the whole native MSVC evaluation pipeline.

Fresh type-policy evaluation of all frozen 250 requests across 45 cells completed
for both baseline and candidate. Eligibility stays 26/250 for both tools/views;
source/ABI perfect remains Fission 0/26 and frozen Kuna 1.808 1/26. Every
function result and exclusion list is identical. This is evaluator regression
evidence, not a new producer run, GED measurement or ranking update.

The local replay harness prepares native debug readers, source indexes and
oracle rows once per immutable image process, independently for baseline and
candidate. Metric caches are disabled and metric results are computed fresh.
An initial unshared attempt exceeded 300 seconds on a large image; it is retained
as incomplete evidence. Nineteen completed cell executions agree with their
unshared controls after excluding only timing/preparation metadata. The final
45-cell replay has no failed or timed-out cell. Complete patch, commands, input
hashes and reports are retained in the Fission workspace under
`benchmark/artifacts/cpp-review-correctness/2026-10-18/`.

PR #91 is still open at this review snapshot. Prerequisite removal/rebase and
exact submitted-head upstream CI remain merge gates. The prior head's green fork
run is not evidence for this unsubmitted delta. Virtual-base cross-format policy
and a future malformed-PDB fuzz/property gate remain separate follow-up work.
