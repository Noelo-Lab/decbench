# Progress Log

Work log for: declib decompiler integration, type metric fix, and interactive web UI.
Date: 2026-06-04

## Environment setup

- Python env: virtualenv at `/home/mahaloz/.virtualenvs/decbench` (Python 3.12).
  Activate with `source /home/mahaloz/.virtualenvs/decbench/bin/activate`.
- Pre-existing in env: `declib 4.0.1` (editable from `~/github/declib`), `angr 9.2.221`,
  `pyghidra 3.1.0`.
- Decompiler installs: IDA Pro 9.2 (`/home/mahaloz/bin/idapro_92`, idalib importable as
  `idapro`), Ghidra 12.1 (`GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1`).
  Binary Ninja: **not installed** (binja support added but untested).
- Installed into the venv: decbench (editable, `pip install --no-deps -e .`) plus
  pydantic, toml, tqdm, networkx, pyelftools, click, rich, capstone, diff-match-patch,
  graphviz, numpy, scipy, ailment, cpgqls-client, psutil, pytest, pytest-cov, black,
  ruff, mypy, and `cfgutils`/`pyjoern` (installed with `--no-deps`).
- `pygraphviz` initially failed to build (needs `libgraphviz-dev`, no passwordless
  sudo). **Worked around without sudo**: downloaded `libgraphviz-dev` via
  `apt-get download`, extracted headers to `~/.local/graphviz-dev/include`, created
  `lib*.so` symlinks in `~/.local/graphviz-dev/lib` pointing at the system runtime
  libs, then `C_INCLUDE_PATH=... LIBRARY_PATH=... pip install pygraphviz`. ✅
- `pyjoern` then auto-downloaded its bundled Joern (~1.9 GB) on first import.
  Verified `parse_source()` extracts CFGs from C source. GED metric fully unblocked.
  (No user action needed after all — the earlier sudo request is obsolete.)

## Workstream 1: declib-backed decompilers — DONE

- Added `VariableInfo` model + `FunctionDecompilation.variables` field
  (`decbench/models/decompilation.py`). Captures per-function stack variables and
  arguments (name/type/stack_offset/size/kind) for the type metric.
- New `decbench/decompilers/declib_dec.py`: `DeclibDecompiler` base class + four
  registered plugins — `ida`, `ghidra`, `binja` (new), `angr` — all driving declib's
  `DecompilerInterface.discover(force_decompiler=..., headless=True, binary_path=...)`.
  - Addresses: declib returns lifted (0-based) addrs; decbench stores ELF-file-space
    addresses (`lifted + min PT_LOAD vaddr`) so they match DWARF for PIE and non-PIE.
  - Function filtering: CRT names skip-list + anything outside the ELF `.text` section
    (kills PLT stubs/import thunks uniformly across backends).
  - Ghidra/IDA get per-(binary, backend) project dirs `declib_<name>_projects/<bin>/`
    (Ghidra forbids dot-prefixed path elements — learned the hard way).
  - Per-function timeouts are advisory only: declib does not expose them.
- Deleted old direct-API plugins: `angr_dec.py`, `ghidra_dec.py`, `ida_dec.py`,
  `old_ghidra_dec.py`. The `angr_phoenix`/`angr_dream` variant names are gone
  (e2e_coreutils_eval.py choices updated).
- `pipeline/decompile.py`: `ProcessPoolExecutor(max_tasks_per_child=1)` (feature-
  detected for py3.10) so JVM/idalib state never leaks across worker tasks.
- `pyproject.toml`: added `declib>=4.0.0` dependency.

### Bug found & fixed in declib (local checkout ~/github/declib)
`declib/decompilers/angr/interface.py::line_map_from_decompilation` crashed with
`AttributeError: 'Label' object has no attribute 'ins_addr'` on angr 9.2.221: modern
angr vendors ailment as `angr.ailment`, so `isinstance(stmt, ailment.statement.Label)`
against the *standalone* `ailment` package never matched. Fixed by importing
`from angr import ailment` (fallback to standalone) and skipping statements without
an `ins_addr`. decbench also retries `map_lines=False` if a line-mapped decompile fails.

### Smoke results (tiny -O0 -g x86-64 binary)
| backend | time  | functions found | names | stack offsets |
|---------|-------|-----------------|-------|----------------|
| angr    | 0.6s  | add_nums, main (+unnamed CRT frags) | synthetic (v0, v1…) | match DWARF space exactly |
| ida     | 0.2s  | add_nums, main  | DWARF names (tag, big, x) | lifted offsets match DWARF space |
| ghidra  | 6.0s  | add_nums, main  | DWARF names | match DWARF space |

Key empirical fact: declib's canonical stack offsets from all three backends coincide
with DWARF `DW_OP_fbreg + 16` offsets (calibration shift 0), e.g. `char tag` ⇒ −21
everywhere.

- `tests/test_decompilers.py`: registry tests + real smoke decompile per backend
  (auto-skip when unavailable; binja is skip-only). 6 passed in ~8s.

## Workstream 2: type_match metric fix — DONE

Root causes of "type metric returns 0 for angr":
1. Matching was by exact variable name; angr emits `v0`/`s_4`/`arg_0` → every GT var
   was a false negative → 0.0 for every function.
2. Deeper: at `-O2` (the example/e2e default) DWARF contains **zero** `DW_OP_fbreg`
   entries (locals live in registers), so ground truth was empty and the metric
   skipped every function for *all* decompilers. Benchmarks must include `O0` for
   this metric to be meaningful (example project + e2e configs updated to O0+O2).

Fix (in `decbench/metrics/type_match.py`):
- **Offset matching (primary)** using `FunctionDecompilation.variables`: GT DWARF
  offsets (`DW_OP_fbreg + 16`, rbp-relative) vs declib canonical stack offsets,
  aligned by an additive shift. Empirically the shift is **8** for angr/IDA/Ghidra
  on x86-64.
- **Binary-level shift calibration** (`_calibrate_shift_multi`): the shift is an
  ABI/decompiler constant, so it is calibrated once per (binary, decompiler) by
  pooling per-function offset sets. Votes are `max(0, unique_matches - 1)` per
  function so a lone junk slot (e.g. angr's `+8` return-address slot) cannot elect
  a spurious shift — this exact failure happened with per-function calibration.
- **Name rescue**: GT stack vars promoted to args/registers by the decompiler
  (e.g. `argc`/`argv` in IDA) are matched by name before counting as misses.
- Fallbacks: name matching over structured vars → regex text extraction (old path,
  keeps old results comparable).
- `normalize_type` improvements: pointer-space canonicalization (`char * *` ==
  `char**`), LP64 `long` == `long long`, TYPE_MAP re-applied after qualifier
  stripping.
- Diagnostics: per-function metadata (`matched_by`, `calibration_shift`, tp/fp/fn,
  stack-var counts) + a binary-level warning explaining all-zero scores.

## Workstream 3: interactive web UI — DONE

- Labels: auto (`O0`/`O2` + `optimized`/`unoptimized`, `large` ≥100 decompiled
  lines) + user labels via `ProjectConfig.labels` / `binary_labels` (TOML). Function
  labels inherit binary labels; `scoring/labels.py` is the extension hook.
- Per-function results persisted to `function_results.json` next to scoreboard.toml
  (`models/function_data.py`, `scoring/function_data_builder.py`).
- `decbench report` (new `--function-data` option, defaults to sibling JSON) embeds
  the data into the self-contained HTML report: label chips + per-binary checkboxes
  that live-recompute ALL scores (stat cards, rankings, Overall) client-side,
  a decompiler comparison matrix, and a per-binary breakdown table. Graceful static
  fallback with a banner when the JSON is missing.
- Aggregator per-function keys widened to `project::opt::binary::function`.
- Verified headlessly with jsdom: 43/43 → disable "O2" label → 16/43 → disable O0
  binary → 0/43 → reset → 43/43; comparison matrix recomputes. All checks passed.

## Additional bugs found & fixed along the way

- **IDA byte_match was 0.0 for every function**: Hex-Rays emits `__cdecl`/
  `__fastcall`/`__int64` etc. which gcc cannot recompile, so byte_match's
  recompilation always failed. The old in-tree IDA plugin only normalized types, not
  calling conventions, so this was broken before the declib port too. Fixed via
  `_normalize_code` in the IDA backend (mean went 0.0 → 0.25, 16/20 functions
  nonzero).
- **Example project ignored the pipeline's optimization level**: the Makefile's
  `CFLAGS =` overrode the env CFLAGS that carry `-O0`/`-O2`, so every "O0" build was
  silently O2. Now `override CFLAGS +=` force-appends benchmark-critical flags while
  letting the pipeline's opt level through (also robust against the user's shell
  exporting CFLAGS — which it does: `-I/opt/homebrew/...`).
- Example project TOML: `pre_make_cmds = ["make clean"]` so per-opt-level rebuilds
  never reuse stale artifacts; local in-place builds should use `-j 1`.

## Benchmark results (example project, O0+O2, 43 distinct functions, ~71s wall)

| metric      | angr        | ida         | ghidra      |
|-------------|-------------|-------------|-------------|
| ged (perfect %)        | 75% | **85%** | 70% |
| type_match (perfect %, O0+O2) | 60% | **90%** | **90%** |
| type_match (mean, O0)  | 0.90 | 1.00 | 1.00 |
| type_match (mean, O2)  | 0.57 | 0.87 | 0.87 |
| byte_match (mean)      | 0.06 | 0.25 | 0.26 |

- The user-visible complaint is resolved: angr's type metric is no longer 0
  (mean 0.33 at O0; remaining misses are genuine — angr loses arg names and
  optimizes locals into SSA expressions).
- byte_match has no perfect functions for anyone — byte-exact recompilation is
  genuinely hard; values are now meaningfully distributed instead of all-zero.
- Overall (perfect on all 3) is 0% for all decompilers, dominated by byte_match.

## Follow-up: type checking at -O2 — DONE

Investigated whether type_match can work at O2 (where the original design scored
nothing because DWARF has no `DW_OP_fbreg` stack offsets). Finding: **the variables
are still in DWARF** — they have register loclists (`DW_OP_reg5 (rdi)`,
`DW_OP_entry_value`, …), names, and types. Only the *stack offsets* are missing.
Two location-independent identities exist and are now used:

1. **Arguments match by ABI position.** DWARF `DW_TAG_formal_parameter` order ==
   ABI register order == declib's `header.args` index — for all backends, including
   angr's nameless `a0`/`a1`. GT extraction now records `is_arg`/`arg_index`
   (position counted over all formal parameters, including dropped ones), and
   `VariableInfo.arg_index` carries the decompiler side.
2. **Register-located variables stay in ground truth.** `_get_location` now returns
   `(offsets, has_location)`; only variables with NO DWARF location at all (fully
   optimized out) are excluded. Register locals match by name (pass 3) when the
   decompiler imported debug names.

Matching is one unified 3-pass algorithm (`_match_structured`, each decompiled
variable claimable once): ① args by position → ② stack vars by calibrated offset →
③ rest by name. `matched_by` metadata is now `structured`/`regex`, with per-pass
counts (`matched_by_arg`/`offset`/`name`).

### O2 results (example project, real decompiler output)
| function | angr | ida | ghidra |
|----------|------|-----|--------|
| classify_number | 1.00 | 1.00 | 1.00 |
| schedule_job    | 1.00 | 1.00 | 1.00 |
| main            | 0.50 | 1.00 | 1.00 |
| job_status      | 0.00 | 1.00 | 1.00 |
| count_to_n      | 0.33 | 0.33 | 0.33 |

All misses are genuine: angr types `argv` as `struct_0*` and `stats` wrong;
`count_to_n`'s `sum`/`i` are register locals that NO decompiler surfaces as named
variables at O2 (IDA shows `v1/v2 // eax/edx`, Ghidra literally prints
"Unresolved local var: int i@[???]") — a fair uniform penalty.

O0 also improved (positional args now credit correctly-typed args even with
synthetic names): angr O0 mean went 0.33 → 0.90.

## Adversarial review round (multi-agent) — 9 confirmed findings, all fixed

A 3-reviewer + per-finding adversarial-verifier pass over the full diff confirmed and
led to fixes for:

1. `_BOOL` → `bool` normalization produced uncompilable C for byte_match (no
   `<stdbool.h>` in its recompile preamble). Fixed: map to `_Bool` + added
   `<stdbool.h>` to byte_match's headers.
2. Name-prefix filtering (`j_`, `_dl_`, …) could silently drop legitimate user
   functions. Fixed: inside `.text` the section filter alone decides; prefixes only
   apply when no `.text` range is available.
3. **TP double-counting** in type_match: one recovered decompiled slot could satisfy
   multiple GT variables (shadowed locals, offset+name-rescue combos). Fixed with
   per-variable consumption tracking (each decompiled var credited at most once) in
   both offset and name matching. Regression test added.
4. `_calibrate_shift_multi`'s single-slot fallback could elect a spurious nonzero
   binary shift and poison every function. Fixed with a zero-preference +
   minimum-confidence guard. Regression test added.
5. DWARF `short int`/`short unsigned int` never matched decompiler `short`/`_WORD`/
   `ushort` (the long-int bridge existed, the short-int one didn't). Fixed in
   `normalize_type`. Regression test added.
6. Label/binary names were interpolated unescaped into HTML attributes — names with
   quotes silently broke filtering; `<` allowed markup injection. Fixed with
   `html.escape` on all user-derived strings (JS side already used `textContent`).
7. `scoreboard.total_functions` was inflated ×(number of metrics) and diverged from
   the JS-recomputed count. Fixed: count distinct `project::opt::binary::function`
   keys.
8. Metric-registry global state leaked between test files (order-dependent failures).
   Fixed with an autouse `tests/conftest.py` fixture restoring built-in metrics.
9. (Same family as 3 — offset-matched + name-rescued double counting; covered by the
   consumption tracking.)

Refuted (no action needed): IDA replacement corrupting identifiers/strings, ±32
calibration range too small, executor clobbering function_results.json on
--skip-evaluate.

## Test status

- Baseline before changes: 37 passed, 1 skipped.
- Final: **60 passed** (incl. 6 real-decompiler smoke tests, 12 type_match unit
  tests, labels/function-data/report tests, conftest registry isolation).
  `ruff check` clean on all touched files.
- Interactive report verified headlessly with jsdom (real DOM, real event wiring).

## declib change (separate repo, ~/github/declib)

One fix committed to the working tree (not committed to git): angr line-map crash —
see "Bug found & fixed in declib" above. Remember to commit it there.
