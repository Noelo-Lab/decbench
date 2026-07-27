# Metrics — how DecBench scores decompilation

Three metrics (`decbench/metrics/`) compare decompiled output to the original
source/binary. Their fairness rules are load-bearing: the shared denominators
and normalization passes below are the benchmark's contract, so investigate
before changing any of them — and bump the metric's `cache_version` if you do
(see [Metric caching](#metric-caching)).

## Structural Correctness — GED (`metrics/ged.py`)

CFG Graph Edit Distance between source and decompiled code. The engine is
`cfgutils.similarity.vj_ged`, which is almost purely structural: it scores
graph topology plus each node's `is_entrypoint`/`is_exitpoint` flags and never
reads labels (which is what makes the published source-CFG serialization
lossless — see [dataset-publishing.md](dataset-publishing.md)).

- Decompiled-side CFGs are parsed from the decompiled C via pyjoern.
- Exact GED is super-polynomial, so runs cap it to CFGs ≤
  `DECBENCH_GED_MAX_NODES` nodes (default 60, read in `metrics/ged.py`) — a
  few huge optimized CFGs would otherwise dominate a run.

### Preprocessed `.i` files are REQUIRED — source CFGs come EXCLUSIVELY from them

`pipeline/evaluate.py` (via `project.preprocessed_sources`),
`scripts/run_benchmark.py`, and `pipeline/executor.py` (which globs
`compiled_dir/*.i`) all build the source-side CFGs by feeding `.i` files to
`utils/cfg.py extract_cfgs_from_source` (system headers stripped, then pyjoern
`parse_source`). `.i` over `.c` is deliberate: Joern needs macro-expanded,
ifdef-resolved code to parse completely — raw `.c` with unexpanded includes
parses incompletely. Without `.i` the pipeline takes the "No preprocessed
sources" branch and **GED is silently None for every function of the run — no
error**.

byte_match/type_match don't use `.i` (`requires_source_cfg = False`;
gcc-recompile and DWARF respectively), and sample source extraction only
*falls back* to `.i`. So do NOT disable `Project.emit_preprocessed` (default
True, `models/project.py`) or `-save-temps=obj` in the default `base_flags`
(`compilers/gcc.py`). The only `.i`-free evaluation path is the
published-dataset `--source-cfgs` flow (precomputed `source_cfgs/*.json`,
built FROM `.i` at publish time by `publish/cfg_export.py`) — and that path
cannot score type_match.

Source-side matching is per-TU: `pipeline/evaluate.py` matches a binary's OWN
translation unit first, cross-TU best-by-name only as fallback (avoids
same-name collisions across TUs). The old JOERN_FAILURES.md failure analysis
lives in git history; Joern parse-health stats render on the site's data page.

## Type Correctness — `metrics/type_match.py`

Compares decompiled variable types against DWARF ground truth (read via
pyelftools). Works at **all opt levels**: ground truth keeps every variable
with ANY DWARF location
(register loclists included; only fully optimized-out vars are dropped).

Unified 3-pass matching against `FunctionDecompilation.variables`:

1. **Arguments by ABI position** — DWARF formal-parameter order ↔
   `VariableInfo.arg_index`; name-independent, so angr's `a0`/`a1` get fair
   credit.
2. **Stack vars by auto-calibrated offset shift.**
3. **Rest by exact name.**

Regex text parsing is the last-resort fallback (and the scoring path for
backends that carry no `VariableInfo`, e.g. LLM agents and external
submissions: the C signature is parsed into ABI-positioned args + locals). At
`-O2`, register locals that decompilers fold into expressions count as misses
for everyone uniformly.

## Recompilation Bytematch — `metrics/byte_match.py`

Assembly similarity after recompiling the decompiled C **the same way the
source was compiled** — the toolchain and `-m*/-O*` flags matching the
original binary's own format+arch (PE→MinGW, ARM→arm-none-eabi, x86→gcc;
flags read from the DWARF producer), via `decbench/utils/binfmt.py`. Returns a
non-scoring result (an **abstention**, not a 0) if that toolchain isn't
installed — don't fake a wrong-arch recompile. Works on ELF and PE.

### The two fairness passes (v5, `cache_version="5"`)

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
   ~83-95% fixed, per decompiler).
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
a recompiled ELF/COFF object. Both type_match and byte_match use it, so they
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
