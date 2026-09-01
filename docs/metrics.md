# Metrics — how DecBench scores decompilation

Three metrics (`decbench/metrics/`) compare decompiled output to the original
source/binary. Their fairness rules are load-bearing: the shared denominators
and normalization passes below are the benchmark's contract, so investigate
before changing any of them — and bump the metric's `cache_version` if you do
(see [Metric caching](#metric-caching)).

## Structural Correctness — GED (`metrics/ged.py`)

CFG Graph Edit Distance between source and decompiled code. A directed
NetworkX isomorphism check handles perfect matches; non-isomorphic graphs use
the cfgutils VJ-GED cost model or the large-graph lower bound. DecBench solves
VJ-GED's assignment matrix with SciPy's compiled linear-assignment solver
instead of cfgutils' equivalent pure-Python Munkres implementation. All three
paths read graph topology plus each node's `is_entrypoint`/`is_exitpoint` roles
and never read labels (which makes the published source-CFG serialization
lossless — see [dataset-publishing.md](dataset-publishing.md)).

- Decompiled-side CFGs are parsed from the decompiled C via pyjoern after
  syntax sanitization and expansion of macros defined in that output. This
  mirrors the source side's macro-expanded input; includes are removed before
  the host preprocessor runs, and preprocessing failure falls back to the
  sanitized text.
- Every pair first receives a directed graph-isomorphism check that includes
  entry/exit roles. An isomorphic pair is always GED 0, regardless of graph
  size. Joint isomorphism-invariant neighborhood colors are attached before
  the same NetworkX check to prune VF2's search on large, structurally similar
  CFGs; they do not filter or approximate any pair.
- Non-isomorphic pairs up to `DECBENCH_GED_MAX_NODES` nodes (default 200,
  read in `metrics/ged.py`) use VJ-GED. Its compiled assignment solver is
  score-equivalent to cfgutils' implementation and makes the 200-node default
  practical. Larger pairs use the nonzero lower bound from their
  node/edge-count differences so a few huge optimized CFGs cannot dominate a
  run. The lower bound is floored at 1 after isomorphism fails, preserving the
  contract that GED 0 means graph-isomorphic.

### Preprocessed `.i`/`.ii` files are REQUIRED — source CFGs come EXCLUSIVELY from them

`pipeline/evaluate.py` (via `project.preprocessed_sources`),
`scripts/run_benchmark.py`, and `pipeline/executor.py` (which globs
`compiled_dir/*.i` and `*.ii`) all build the source-side CFGs by feeding the
preprocessed units to `utils/cfg.py extract_cfgs_from_source` (system headers
stripped, then pyjoern `parse_source`). Preprocessed over raw source is
deliberate: Joern needs macro-expanded, ifdef-resolved code to parse
completely — raw `.c` with unexpanded includes parses incompletely. Without
them the pipeline takes the "No preprocessed sources" branch and **GED is
silently None for every function of the run — no error**.

The extractor writes stripped `.i` text to a temporary `.c` file and stripped
`.ii` text to a temporary `.cpp` file because Joern chooses its frontend from
that suffix. It does not read or fall back to the project's original source.

gcc names the preprocessed output after the LANGUAGE, not the flag: a C unit
yields `.i` and a C++ unit `.ii`. Joern picks its frontend the same way, and
its **C frontend returns ZERO functions for C++ input** — so `utils/cfg.py`
chooses the temp-file suffix from the input (`.ii` -> `.cpp`, `.i` -> `.c`)
via `temp_parse_suffix`. Handing a `.ii` to Joern as `.c` scores nothing at
all (measured on a leveldb TU: 0 functions as `.c`, 393 as `.cpp`).

Every collection site therefore globs BOTH extensions through
`utils/langs.py preprocessed_by_stem` — `pipeline/executor.py`,
`evalkit/ingest.py`, `scripts/reeval_ged.py`, `scripts/run_small.py`,
`scripts/cps_compile_smoke.py`. A site that hard-codes `*.i` does not error on a
C++ project; it reports "no sources" and every source-side metric silently
abstains, which is how `scripts/reeval_ged.py` produced a `ged_new.json` with no
C++ entries at all. The **only** remaining `*.i`-only globs are the
dataset/publish family — `publish/cfg_export.py`, `publish/layout.py`,
`dataset.py`, `scripts/compute_dataset_info.py` — which is why a C++ project is
not publishable to the dataset yet (see benchmarking.md).

byte_match does not use the preprocessed units (`requires_source_cfg = False`;
it recompiles the decompiled code). type_match still reads its denominator and
types from DWARF, but now also uses `.i`/`.ii` units to construct source
evidence: both `.i` and `.ii` units supply the native address channel. Without a
usable unit, type_match falls back to ABI argument and stack anchors. Sample source extraction only *falls back* to them.
So do NOT disable `Project.emit_preprocessed` (default True,
`models/project.py`) or `-save-temps=obj` in the default `base_flags`
(`compilers/gcc.py`). The only preprocessed-free evaluation path is the
published-dataset `--source-cfgs` flow (precomputed `source_cfgs/*.json`, built
FROM the preprocessed units at publish time by `publish/cfg_export.py`) — and
that path cannot score type_match. The publish/dataset paths still glob only
`*.i` (`publish/layout.py`, `publish/cfg_export.py`, `dataset.py`,
`scripts/compute_dataset_info.py`), so a C++ project cannot be published to the
dataset yet.

Source-side matching is per-TU: each target function's DWARF `low_pc` and
`DW_AT_decl_file` select its defining preprocessed translation unit first. The
binary-stem convention is retained when that provenance is unavailable, and
cross-TU best-by-name is only the final fallback. This matters when a build
names an output differently from the source that defines its `main`; using the
largest same-named graph from another TU is not valid ground truth. Matching is
also per optimization level: an O0 source CFG is not valid ground truth for O2
merely because both inputs came from the same project. The old
JOERN_FAILURES.md failure analysis lives in git history; Joern parse-health
stats render on the site's data page.

The live evaluator, external eval-kit ingestion, dataset CFG export, and
canonical `reeval_ged.py` overlay all use this ownership rule.

**C++ name collisions.** Matching is by UNQUALIFIED name on both sides (DWARF
`DW_AT_name` is `Get`, not `leveldb::DBImpl::Get`, and Joern's C++ frontend
keys on the short name too — so no demangler is involved anywhere). A C++
binary therefore collapses every same-named method onto one entry: leveldb has
7-8 `Next`/`Seek`/`SeekToFirst`/`Name` methods, one per iterator class, and
they are all scored against whichever body won `best_source_by_name`. A C++
target's absolute GED is consequently **not comparable to a C project's** —
compare C++ targets to each other. Qualified-name keying (Joern `fullName` +
DWARF parent-DIE walking) is the fix and is not implemented.

## Type Correctness — `metrics/type_match.py`

Compares decompiled variable types against DWARF ground truth (read via
pyelftools). Works at **all opt levels**: ground truth keeps every variable
with ANY DWARF location
(register loclists included; only fully optimized-out vars are dropped).
Current `cache_version="14"`. Version 14 splits scoring into two correspondence paths
(see [Two correspondence paths](#two-correspondence-paths)): a producer that carries
instruction-address provenance keeps the address correspondence unchanged, while a
producer that carries none at all falls back to the legacy name-based correspondence
instead of scoring residual variables not at all. Version 13 removed the `usage` and `address+usage`
correspondence modes: address evidence is now the only correspondence channel, so the
matcher no longer builds type-blind C usage feature vectors and the per-function key no
longer carries them. Version 12 masks the ARM Thumb bit off a function
entry address before joining it to DWARF, so a Thumb function whose static name
repeats across translation units resolves to its own ground truth instead of
being dropped; only backends that report tagged addresses (angr) are affected.
Version 11 makes producer-supplied structured
variable occurrence fields authoritative: an empty `line_numbers`/`addresses`
pair is an abstention and is never repopulated by matching the variable's spelling
against rendered C. Version 10 began honoring the ELF ARM architecture profile
when decoding Cortex-M Thumb. Version 9 expanded native source evidence from x86
ELF to cross-format x86, ARM/Thumb, and AArch64 executable regions and made
line-table file indexes follow the line program's own DWARF version.
The per-function key covers the matcher policy,
redacted address/anchor evidence, the stack shift, decompiled types used
for grading, and DWARF ground truth. It does NOT cover `normalize_type`, so a
normalization-policy change still requires a version bump (see
[Metric caching](#metric-caching)).

Production ground truth is indexed by the top-level subprogram's address and
name. This prevents two static or C++ functions with the same unqualified name
from overwriting one another; a unique-name fallback remains available when a
non-ELF backend uses a different address space. The legacy name-only extraction
helper omits ambiguous names rather than choosing one. This qualification does
not change the variable denominator within the selected subprogram: variables
from its existing inlined-subroutine traversal remain included.

**The ground-truth payload must be ORDER-STABLE.** `_parse_variable_die` returns
`type` and `rbp_offset` as SORTED lists. They land in the cache key through
`stable_hash` → `json.dumps(sort_keys=True)`, which orders dict keys but not list
elements, so building them with `list(set(...))` made the key depend on
`PYTHONHASHSEED` and the disk cache mostly missed across processes (measured on
bzip2/ghidra, 108 functions: cold 5 hits / 103 misses, then a second process at
the default random seed 25/83 and a third 51/57 — versus 108/0 with sorted
lists). Any new list in that payload must be sorted too.

### Two correspondence paths

Which correspondence a function is scored through depends on the **declared capability
of the backend that produced it**, never on what a particular checkpoint happens to
contain. `LEGACY_CORRESPONDENCE_BACKENDS` names the backends whose final output cannot
carry machine-to-variable lineage at all — their AST discards it (Glaurung, Manifold) or
they emit only text (the LLM agents, external text-only submissions). Everything else,
and anything unlisted, takes the address path.

Declared rather than measured is load-bearing, not a style choice. A checkpoint can lack
per-variable provenance for reasons that have nothing to do with the backend: the
canonical `results/full_run` checkpoints store line mappings **without** per-variable
addresses for every backend, IDA and Ghidra included. A predicate that probed the data
would read those as address-incapable and silently move the entire published leaderboard
onto exact-name matching, caveating every row. `compute_for_binary` therefore resolves
the choice from `decompiler_name` alone, once per `DecompilationResult`.

Producer scope rather than function scope also matters: an address-capable backend
routinely emits individual functions with no addressed variable (measured: 12 of 107 IDA
functions in `bzip2` at `-O0`), and a per-function rule would both switch those rows onto
name matching and make two identical outputs score differently depending on whether an
unrelated sibling function carried an address. The declaration is explicit, not implied:
`address_provenance=None` — any caller that does not declare — keeps the address
correspondence, so only a deliberate `False` selects the legacy path.

- **Address correspondence** (angr, Binary Ninja, Ghidra, IDA, Kuna, r2dec, dewolf, Reko,
  annotated RetDec). Unchanged, type-blind, and described below. Variable names are never
  matching evidence on this path, and stack offsets come only from an explicit
  `VariableInfo.stack_offset`. Rows record `correspondence: "address"`.
- **Legacy name correspondence** (Glaurung, Manifold, the LLM/coding-agent backends,
  imported eval-kit C — any producer with no address provenance anywhere in its output).
  This is the pre-provenance matcher preserved verbatim as `_match_structured` /
  `_match_by_regex`: ABI argument position, then calibrated stack offset — including an
  offset recovered from a `local_XX` / `var_XX` name via `_legacy_effective_offset` —
  then **exact variable name**, with a regex declaration parse when the producer exposes
  no structured variables at all. Rows record `correspondence: "legacy_name"`.

Name-derived offsets and exact-name matching are not sound evidence, and they are
unreachable from the address path: `_legacy_effective_offset` is called only from
`_match_structured` and the legacy stack-variable count. That keeps the type-blind
guarantee for every address-capable backend intact while giving a name-only producer a
score at all.

Legacy rows are **not measured the same way** and are caveated accordingly. Each one
reports `variable_match_evidence: "fallback_only"`, which is the existing category the
report, the site, and `typematch_ab`'s `asterisk_recommended` already treat as a
measurement caveat — no parallel mechanism was added. They also report
`linemap_present: false`, zero `decompiler_address_variables`, and the producer's own
declared `producer_variable_occurrence_policy` (`unavailable`/`undeclared` for every
current legacy producer, which independently triggers the same asterisk). They report
`structured_occurrence_mode: "producer"`, which on this path asserts only what that guard
exists to assert — that no experimental regex occurrence synthesis was used.

Measured effect on Glaurung (`full_glaurung` checkpoints, uncached): `bzip2` `-O0`
97 functions, mean `0.3153 → 0.6028`, 61 functions improved and 0 regressed;
`gzip` `-O0` 134 functions, mean `0.3391 → 0.6723`, 84 improved and 0 regressed.
No address-capable slice moves at all.

### The address correspondence

Variable correspondence is selected **before** recovered types are graded.
The matcher receives no variable names, types, or sizes. There is exactly one
correspondence channel on this path, **address evidence**: unique ABI argument positions and
calibrated stack slots are accepted first, then variables are paired by
ambiguity-checked weighted overlap between source instruction addresses and
decompiler line-map addresses. A prototype `usage` channel and a stacked
`address+usage` fusion were evaluated and removed — they were too unpredictable
to publish — so there is no mode selector and no `variable_match_mode` option.

**The production policy is a fixed constant** (`_VARIABLE_MATCH_DEFAULTS` in
`type_match.py`): address overlap threshold `0.10` and address ambiguity margin
`0.03`.
Variable-size compatibility is **always false** — the matcher is called with
`use_size_compatibility=False`, and a scoreboard that tries to switch it on via
`variable_match_policy` is rejected outright, because byte width is part of the
answer TypeMatch grades. The `min_overlap=0.1` / `ambiguity_margin=0.03` pair is
a pre-existing frozen baseline, carried forward unchanged.
A scoreboard may override either threshold through the metric's
`variable_match_policy` option (unknown keys raise, and every threshold/margin
must be non-negative). The
policy is part of the per-function cache key, so an override re-keys itself and
needs no `cache_version` bump; changing the correspondence *algorithm* still
does.

C source evidence is selected by the function address's DWARF compilation unit
and its path-qualified preprocessor line marker, then joined to DWARF variables
by stable DIE identity. Each C translation unit's exact-name function index is
built once; the sole-definition fallback is forbidden because it can attribute
an unrelated body to the requested function. If DWARF pinning is unavailable,
only one unambiguous exact C definition is accepted. C++ follows the same native
address path. Optional selection or native-extraction failures retain every
DWARF variable in the denominator and fall back to the remaining anchors. The
decompiler side
uses `VariableInfo.addresses` directly, or derives them from
`VariableInfo.line_numbers` plus `FunctionDecompilation.line_mappings`.
The source-side instruction-address adapter reads executable regions and the
Capstone architecture through `utils/binfmt.py`. It supports x86/x86-64,
ARM/Thumb, and AArch64 code in ELF and PE; ARM ELF function symbols select
Thumb mode, and the ELF ARM architecture profile enables Capstone's M-class
instructions. Source instructions therefore use the same virtual/file-space
coordinates as decompiler line maps instead of assuming an x86 `.text`
section. DWARF file indexes follow the line table's own version because an
object may pair a DWARF v5 compilation unit with a pre-v5 line program.
Unsupported formats or architectures transparently continue with
argument/stack anchors alone.
An address-capable backend's functions without those fields remain scorable through ABI
argument positions and explicit stack offsets, and exact variable names are never a
matching fallback there. At `-O2`, a register local with no address and no anchor
remains a false negative. A producer with no address provenance anywhere takes the
legacy name correspondence instead (see
[Two correspondence paths](#two-correspondence-paths)).

The denominator is unchanged: every retained DWARF variable is graded, even if
it has no observable correspondence evidence. Metadata records accepted-stage
provenance as `variable_match_evidence`, plus stage counts, observable counts,
and line-map presence. The address path emits only `native`; the legacy name path emits
`fallback_only` for every row it scores. The reporting path also still reads the
historical `mixed` category so older overlays and function data stay loadable. On the
address path the field is absent when correspondence accepted no pair, because no
evidence channel was actually used. These values support the report's
measurement caveat without publishing variable names, addresses, stable
identities, types, or absolute source paths.

**Candidate discovery.** A backend that ships no structured variable list at all
is not scored as having zero variables: the metric parses candidates out of its
own rendered C instead (`parse_c_variables`), and marks them `inferred_from_code`.
Discovery uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) and its
C grammar (`metrics/variable_features.py`) — this is why `tree-sitter` and
`tree-sitter-c` are runtime, not dev, dependencies; the same parser backs the
decompiler line-provenance path (`variable_occurrence_lines`) and each preprocessed
`.i` unit's exact-name function index (`index_c_functions`). Tree-sitter is used
precisely because it keeps usable concrete-syntax subtrees in imperfect pseudocode,
including *underneath* parse-error nodes. If a decompiler returns only a
statement/body fragment with no `function_definition` node at all, the extractor
wraps the body in a synthetic function and reparses once; if the text contains any
`function_definition` at all and none of them carries the requested name, that is
an explicit abstention rather than a guess. Discovery takes parameters and
body-local declarators, skipping `typedef` and `extern` storage classes and bare
function prototypes. Unnamed decompiler candidates are admitted
(`include_unnamed=True`).

**Discovered candidates are sanitized.** A candidate recovered from rendered C
carries no trustworthy machine evidence, so before matching it loses its
addresses, line numbers, and live ranges, and it is dropped outright unless it
still has a reliable anchor — an ABI argument index or an explicit stack offset.
This is what keeps the numbers honest for text-only backends: they cannot earn
address-channel credit from evidence that was reverse-engineered out of their own
output.

**The type exclusions are load-bearing.** Names and sizes are cleared before
correspondence and size-compatible matching is disabled, because the
correspondence exists to grade recovered types and any of them would leak the
answer.

For checkpoint A/B runs, `scripts/reeval_typematch.py` prints old/new comparisons.
Non-canonical overlays require an explicit
`--output`; only `--emit` may write `type_match_new.json`. `--output`
cannot alias the canonical path. `--manifest sample_set_manifest.json` filters
the rows emitted to a non-canonical sample-set replay and cannot be combined with
`--emit`. For every selected binary, however, sanitization and
binary-wide stack-offset calibration see the producer's complete function set; only
the resulting overlay rows are manifest-filtered. A partial manifest therefore cannot
change the calibration of a retained function. Repeatable `--backend NAME` selectors
avoid replaying unrelated checkpoint columns and are likewise forbidden for canonical
`--emit` promotion. A requested backend that produces no scores fails instead of
writing a misleading empty overlay. Written overlays retain the legacy raw score-map
shape and gain a digest-bound `.meta.json` companion containing the matcher mode
(now always `address`), complete policy values, policy/manifest schemas, and metric
cache version. Scoped updates require compatible provenance and refuse legacy or mixed-policy
merges. Every overlay write is transactional, including explicitly named A/B
outputs. A missing checkpoint, binary-relocation failure, scoring exception,
reported metric error, or coverage mismatch leaves the existing overlay and companion
unchanged. Coverage is exact for the invocation: required rows are the functions
actually present in each selected producer checkpoint intersected with the frozen
global TypeMatch-measurable denominator in `function_results.json`. This permits a
real decompiler omission while rejecting a silently dropped metric row, even when
every A/B overlay would otherwise drop the same row. Explicit A/B outputs remain usable
for partial experiments through a sample manifest or project scope, with that same
fail-closed check applied before a scoped merge.

An explicitly named A/B output may instead use
`--function-data /path/to/frozen/function_results.json`. This supports comparisons
between result trees whose locally finalized function sets differ while retaining one
common denominator; it is forbidden for canonical promotion. The output overlay and
its metadata may not alias that denominator or the selected manifest. The corpus-scale
orchestrator additionally binds the external file's absolute path, size, digest,
selected count, measurable count, and key digest into the run plan and revalidates it
throughout the run.

Before scoring each checkpoint result, the re-evaluator resolves the binary in
the selected results tree, deep-copies and relocates the result, and applies the
same strict native-provenance sanitizer as a fresh run. Thus TypeMatch v11 can
reuse valid subsets of historical IDA/Kuna/native evidence without trusting
cross-function, padding, or instruction-interior claims. This is in-memory only:
the raw checkpoint pickle is never rewritten. Pickles created before additive
variable-line/address fields existed are hydrated with empty lists at this boundary;
the sanitizer records the number of hydrated fields and never treats schema repair as
native evidence. Retired Phoenix checkpoints receive one additional in-memory step:
because their saved C and native position map came from the same angr code-generator
object, exact unique final identifiers are joined to surviving sanitized rows. Parse
errors, stale or duplicate rows, name shadowing, a mismatched function definition, and
variables without a mapped occurrence all abstain. No other legacy backend receives
this repair without an equivalent same-render producer contract. The in-memory result
declares those exact occurrences through the same producer policy metadata as a fresh
backend. The checkpoint's outer binary, backend, and function keys must exactly match
the corresponding stored model identities. Only the stale `binary_path` is permitted
to differ because relocation deliberately replaces it.

Every fresh function declares a versioned `variable_occurrence_policy` in its
metadata: `exact` for final-render line/variable identity, `direct` for sound
variable addresses without a stable render-line callback, or `unavailable` for
intentional abstention. Missing declarations on legacy checkpoints also fail closed.
The production metric always uses `structured_occurrence_mode="producer"` and records
both the declaration and mode in per-function diagnostics. The extractor retains an
explicitly named `experimental_legacy_regex` API for isolated v10 comparisons, but no
production adapter or metric configuration enables it.

TypeMatch v11 overlays retain each scored function's producer occurrence policy as
`producer_variable_occurrence_policy` and its `structured_occurrence_mode`. Their
digest-bound manifest also records the policy schema and
`structured_occurrence_mode="producer"`. The overlay storage boundary rejects v11+
manifests with any other occurrence mode or schema and rejects every v11+ score row
without a recognized `exact`, `direct`, `unavailable`, or legacy `undeclared` policy.
The A/B reporter reports those policies separately from accepted-evidence categories
and the measurement-undercount asterisk.

Summarize independently generated overlays with the shared-denominator reporter,
not the re-evaluator's own console mean:

```bash
python scripts/report_typematch_ab.py \
  --function-data results/full_run/function_results.json \
  --results-root results/full_run \
  --manifest results/full_run/sample_set_manifest.json \
  --mode address=/tmp/type-ab/address.json \
  --baseline-mode address \
  --checkpoint-dir /tmp/pr48-native-sample/checkpoints \
  --output /tmp/type-ab/report.json \
  --markdown /tmp/type-ab/report.md
```

The report validates every overlay's digest-bound policy/cache provenance and
requires identical per-backend score keys across overlays. It reports two different
statistics deliberately: the conditional partial mean uses only finite scores,
while the published Type percentage counts perfect functions over the shared set
where any backend measured TypeMatch. A backend's missing score is therefore a
not-perfect miss in the latter. Coverage gains/losses, paired regressions, evidence
category transitions, architecture/format strata, and optimization-level strata
remain explicit. The schema-v2 JSON records full score, comparison, and producer
evidence summaries for each optimization level. The concise Markdown shows each
backend's baseline-to-candidate published perfect rate and percentage-point delta
separately for `O0`, `O2`, and `O2-noinline`, so a conditional mean across
optimization levels cannot be mistaken for the published unoptimized percentage.
Passing `--checkpoint-dir` additionally audits actual function line maps and
variable-line / variable-address fields; a line map without variable occurrence
addresses is not claimed as usable correspondence evidence. The JSON is canonical;
Markdown contains only the review headline. Invalid scope or provenance still writes
the diagnostic report but exits nonzero unless `--allow-invalid` is requested.

At corpus scale, `scripts/run_typematch_ab_sharded.py` is the supported wrapper around the
partitioner, re-evaluator, and reporter. It always evaluates the production address
correspondence over
whole-binary shards so binary-wide stack calibration cannot drift, and its fixed denominator
is the selected manifest intersected with the globally TypeMatch-measurable functions in the
bound `function_results.json`. Expected overlay rows are narrower and exact per backend:
functions present in that producer's checkpoint intersected with the fixed denominator.
Consequently a real producer omission remains a reported miss, while a scoring exception or
silently missing metric row aborts the worker. Per-worker fresh caches are sealed read-only
and digest-bound alongside the overlay, provenance sidecar, and transcript before resume can
reuse them. The final receipt binds the exact checkpoint/source/binary/code inventories and
the exact non-overlapping union used by the merged, non-canonical overlay.

The reporting path accepts
`MetricValue.metadata["variable_match_evidence"]` as `native`, `mixed`, or
`fallback_only`, based on the evidence actually used for that function rather than
the backend's name. `native` is the address correspondence and `fallback_only` is the
legacy name correspondence; `mixed` described the removed usage channel and is retained
on the reading side only so older overlays and function data stay loadable. The
companion `correspondence` field (`address` / `legacy_name`) names the path in plain
terms for a reviewer reading raw metadata. This provenance is carried through
`FunctionRecord.metric_evidence`
and the site's `metric_evidence` aggregate. The row's
`producer_variable_occurrence_policy` is independently carried through the matching
`FunctionRecord` field and aggregate. A Type percentage receives an explanatory
asterisk for mixed/fallback-only accepted evidence or for an unavailable/undeclared
producer policy. Keeping the channels independent includes measured functions where
correspondence accepted no pair and `variable_match_evidence` is therefore absent.
The provenance never changes a metric value, perfect flag, shared denominator, Union,
or sort order. Function data written before either provenance field existed remains
loadable and is not assigned a guessed category.

A subprogram's name is read through `binfmt.die_attr` rather than straight off
the DIE, because gcc keeps a C++ out-of-line member definition's `DW_AT_name`
on the in-class declaration it references. Without that chase, leveldb's
ground truth is 97 functions instead of 4,236. See
[DWARF reference chains](#dwarf-reference-chains-c-vs-c) for why this does not
change any C value.

### Type-string normalization (`normalize_type`)

A type matches when the ground-truth and decompiled form SETS intersect, so
`normalize_type` returns every equivalent spelling of one type string. Adding a
form can only ever create a match, never destroy one; *removing* a rule (as the
pointee narrowing below does) can only destroy matches. Both directions are
scoring-policy changes and must bump `cache_version`.

- **`TYPE_MAP` applies through pointers, but only for COMMITTED pointees.**
  `int4 *` normalizes to `int*` exactly as the scalar `int4` normalizes to
  `int`, and `size_t *` to `long long*`. **This does declare new equivalences**
  — every same-width, sign-agnostic pair the scalar table already equates now
  also holds one indirection out (`int32_t*` ↔ `int*`, `int64_t*` ↔ `size_t*`,
  `uchar *` ↔ `unsigned char*`). Enumerated over the C corpus (838 binary×opt
  slices, 3,693 decompiled and 3,102 ground-truth spellings), the rule turns
  **152 (decompiled, ground-truth) spelling pairs from a miss into a match**;
  the earlier claim that it "declares no new equivalence" was false.

  What it must NOT do is credit a *non-recovery*. `_POINTEE_MAP` therefore
  excludes the nine TYPE_MAP rows that name a WIDTH rather than a type —
  `undefined`/`undefined1`/`undefined2`/`undefined4`/`undefined8` (Ghidra's and
  kuna's `TYPE_UNKNOWN`) and `_BYTE`/`_WORD`/`_DWORD`/`_QWORD` (Hex-Rays'
  unknown-width slots). `undefined8 *` is "pointer to 8 unknown bytes" and stays
  a **miss** against `size_t*`, matching `_uncommitted_size`'s rule that a
  width-only spelling against a pointer is a real miss. Routing the whole table
  through the pointer instead (the state between PRs #60 and #65) declared 203
  pairs equal, 51 of them with a placeholder pointee.

  The excluded set is deliberately NARROWER than `_UNCOMMITTED_TYPES`, which is
  a *generosity* rule (which spellings may match any same-width scalar) rather
  than a claim that its members fail to name a type. IDA's `__int8`, Ghidra's
  `uchar`, and kuna's `int4`/`int8` are committed integer spellings — each of
  those decompilers emits a *separate* placeholder for an unrecovered slot
  (`_BYTE`, `undefined1`, and kuna's `xunknown4`, which prints as `undefined4`),
  so choosing the named spelling is evidence of a real recovery. Excluding them
  as well would cost IDA 9 of its 37 perfect functions on grep (mean −0.033)
  for no gain in correctness.

  Both sides of the comparison go through `normalize_type`, so the rule applies
  to the DWARF payload as well. On C that is measurably a no-op: `_parse_type_die`
  already walks the whole typedef chain and returns every name, so a ground-truth
  `size_t*` already carries `long unsigned int*` → `long long*`. The ground-truth
  payload hash is **identical with and without the rule on all 690 C binaries**.
- **C++ namespace qualifiers are stripped.** DWARF records a class or typedef
  under its UNQUALIFIED `DW_AT_name` (`TableBuilder`), so a decompiler printing
  `leveldb::TableBuilder *` needs the qualifier dropped to reach ground truth.
  Only `identifier::` tokens are removed, which cannot start with a digit — a
  Ghidra symbol-version prefix like `GLIBC_2.2.5::stderr` is left alone. C
  spellings gain no forms from this rule.
- **A C++ reference is ground truth as a pointer.** `DW_TAG_reference_type` and
  `DW_TAG_rvalue_reference_type` share the `DW_TAG_pointer_type` arm of
  `_parse_type_die`, because a reference is a pointer in the ABI and every
  decompiler renders it as one. Without it every reference-typed ground-truth
  variable was `void` and unmatchable for all decompilers (17.5% of leveldb's).
  C has no reference DIEs, so this rule cannot move a C result.

### Argument positions must be ABI positions

Pass 1 pairs a DWARF formal parameter with the decompiled variable carrying the
same `arg_index`, so a backend that fills `arg_index` in any other order
silently scores itself against the wrong ground-truth variable. Hex-Rays'
`cfunc.get_lvars()` enumerates in allocation order, NOT declared order, so
`decompilers/raw/ida_raw.py` takes positions from `cfunc.argidx`. Any new
backend must do the same.

### DWARF reference chains (C vs C++)

`utils/binfmt.py` `die_attr` / `die_str_attr` / `die_attr_owner` read a DIE
attribute through the reference chain gcc uses to split a definition from its
declaration. The two reference attributes are NOT equivalent:

- **`DW_AT_specification`** is C++-only (out-of-line member definition ->
  in-class declaration). Following it can never change a C result, so it is
  always followed.
- **`DW_AT_abstract_origin`** is used in C too — for the out-of-line copy gcc
  keeps of a function it also inlined. Following it in C would newly surface
  ~10-20% more functions in the pinned corpus (measured on grep at O2: 262 ->
  314 DWARF subprograms). It is therefore followed **only in a C++
  compilation unit** (`binfmt.cu_is_cxx`, on `DW_AT_language`), which keeps
  every existing C binary bit-identical. Enabling it for C is a deliberate,
  corpus-invalidating change that has not been made.

## Recompilation Bytematch — `metrics/byte_match.py`

Assembly similarity after recompiling the decompiled C **the same way the
source was compiled** — the toolchain and `-m*/-O*` flags matching the
original binary's own format+arch (PE→MinGW, ARM→arm-none-eabi, and bare `gcc`
only for an architecture the host builds natively — the cross triplet
otherwise; flags read from the DWARF producer), via `decbench/utils/binfmt.py`.
Returns a non-scoring result (an **abstention**, not a 0) if that toolchain
isn't installed — don't fake a wrong-arch recompile. Works on ELF and PE.

### The two fairness passes (`cache_version="7"`)

Raw decompiler output rarely recompiles as-is (pseudo-types like
`undefined4`, illegal tokens like `GLIBC_2.2.5::stderr`), so naive
recompilation scores almost everything 0. To measure *logic* recovery fairly,
byte_match applies the same two passes to every decompiler. Investigate
before changing them, and bump `cache_version` if you do:

1. **Compilability fixup** (`decbench/metrics/fixup.py` — full details in its
   docstrings) so decompiler output actually builds instead of auto-scoring 0:
   token sanitization plus a **deterministic, gcc-diagnostic-driven
   self-repair loop** that
   injects ONLY what the compiler reports missing (pseudo-type typedefs,
   IDA/Ghidra helper macros, libc + the decompiler's OWN sibling prototypes
   via `derive_context_decls`, synthesized structs, width-typed globals,
   positional edits) and never redefines what the decompiler declared. This
   *maximizes compilation* uniformly (sailr O0 compile rate ~20-79% raw →
   ~83-95% fixed, per decompiler). If the flags passed to
   `compile_with_fixup` contain no explicit language mode, the fixup uses
   `-std=gnu17`; explicit `-ansi`/`--ansi` and `-std`/`--std` modes remain
   unchanged.
   The loop keeps implicit-function-declaration diagnostics visible so it can
   inject prototypes, while trailing
   `-Wno-error=incompatible-pointer-types` and `-Wno-error=int-conversion`
   flags prevent type-recovery mistakes from blocking this byte-level metric.
   A terminal failure retains a deterministic summary of compiler error
   messages and warning-class tags in the per-function metadata, bounded to
   400 characters and stripped of paths, source excerpts, carets, and notes.
2. **Operand normalization** in `_disassemble_bytes` (byte_match.py) blanks
   link-time-dependent operands (direct branch/call targets, rip/pc-relative
   memory INCLUDING the unlinked object's bare `[rip]` form) and drops x86-64
   varargs AL-zeroing from both listings.

`binfmt.producer_flags` also carries codegen `-f` flags from the DWARF
producer — dropping them made whole projects unwinnable. The metric still
records `compilable` per function (the report's per-decompiler **Compiles
rate**, rendered on the data page). Type recovery is measured separately by
type_match, so fixing types to compile is fair.

Known accepted limit: a normalized bare `[rip]` does not compare symbol
identity, so reads of *different* globals can both reach 1.0.

## Shared binary-format helper — `decbench/utils/binfmt.py`

Detects ELF/PE + arch, picks the matching recompiler + capstone arch, reads
DWARF from ELF *or* PE (PE: `.debug_*` sections via objdump file offsets →
pyelftools, since LIEF's community build has no DWARF reader and PE COFF
truncates section names), and extracts function bytes from a final ELF/PE or
a recompiled ELF/COFF object. It also exposes executable virtual-address regions
for source-variable provenance. Both type_match and byte_match use it, so they
work on the PE (MinGW) malware targets.

## Metric caching

`decbench/caching.py` is a content-addressed on-disk cache. Each metric's
`compute_for_function` keys on a `stable_hash` of its determining inputs
(GED: both CFG structures; type_match: vars + DWARF ground truth +
calibration shift; byte_match: code + original function bytes), so re-runs
over seen (decompiled, source) pairs skip recomputation.

- **Caching is deterministic by content: if you change a metric's algorithm,
  bump its `cache_version` class attr** — else stale values are served — or
  run with `DECBENCH_NO_CACHE=1`.
- Diagnostic fields returned from cached values must also be key inputs. For
  type_match this includes line-map presence and the selected source basename;
  omitting them can return another function's otherwise score-equivalent
  provenance metadata.
- The converse also matters: a change that is **provably a no-op for existing
  input** must NOT bump `cache_version`, because the frozen rival checkpoints
  are pinned and a needless bump forces a corpus-wide recompute. The C++
  `DW_AT_specification` chase is the worked example — see
  [DWARF reference chains](#dwarf-reference-chains-c-vs-c).
- **Keep every key input order-stable.** `stable_hash` canonicalizes through
  `json.dumps(sort_keys=True)`, which orders dict keys but NOT list elements, so
  a `list(set(...))` anywhere in a key input makes the key depend on
  `PYTHONHASHSEED` and the cache misses across processes while still being
  fail-safe (a miss just recomputes). Sort such lists at construction, and pin
  `PYTHONHASHSEED` when measuring cache behaviour.
- Cache root: `DECBENCH_CACHE_DIR`; disable entirely with
  `DECBENCH_NO_CACHE=1`.

## Where the numbers surface

Per-function results aggregate through `decbench/scoring/` — `aggregator.py`
(`project::opt::binary::function` keys), `scoreboard.py` (per-metric rankings
+ Union), and `function_data_builder.py` (the per-function `FunctionData`
persisted as `function_results.json`) — into `scoreboard.toml` +
`function_results.json`. The summary **Union** column = perfect on ≥1
measurable metric, over functions with ≥1 measurable metric (stored in the
legacy `overall_*` fields / `overall` JSON keys). The full denominator
semantics — the fairness contract shared with the site — are specified in
[site.md](site.md#denominator-semantics-must-not-drift). The published
numbers come from the reeval overlays + guarded finalize, not raw checkpoint
values — see [benchmarking.md](benchmarking.md#overlays-finalize-and-rebuilds--where-the-published-numbers-come-from).
