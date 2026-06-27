# Progress Log

Work log for: declib decompiler integration, type metric fix, and interactive web UI.
Date: 2026-06-04

---

# Target Expansion: 26 SAILR Debian packages + O2-noinline
Date: 2026-06-07

Goal: grow decbench's target set to all 26 open-source Debian packages from the
SAILR evaluation (`~/github/sailr-eval/targets`), build each with and without
optimizations (plus an inlining-disabled variant), categorize them, and do a
full benchmark run recording results for every supported decompiler.

## Environment rebuild (this machine had none of the documented setup)

The venv/decompilers/declib described in the older notes were **absent** and were
rebuilt from scratch:
- venv `/home/mahaloz/.virtualenvs/decbench` (Python 3.10, `python -m venv`;
  system `virtualenv` makes a broken `local/bin` layout here). decbench editable.
- Decompilers available: **angr 9.2.213 + Ghidra 12.1** (pyghidra 3.1.0,
  `GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1`). **IDA 9.x / Binary Ninja
  are NOT installable here** (only an unusable IDA 8.0 exists) → runs use
  `-d angr -d ghidra`. declib 4.0.1 from PyPI (no `~/github/declib` checkout).
- **GED metric was silently broken**: pyjoern 4.0.150.4 shipped a MISMATCHED
  joern-cli bundle (Joern 1.2.18 jars under a 4.x wrapper that calls `--param`),
  so `parse_source` failed and GED scored nothing. Fixed by dropping the matching
  Joern **v4.0.150** `joern-cli` into `site-packages/pyjoern/bin/joern-cli/`
  (zip SHA-512 must equal `pyjoern.__init__.JOERN_ZIP_HASH`). After that all 3
  metrics work; `test_ged_pipeline` passes. Re-apply after any pyjoern reinstall.

## Workstream A: O2-noinline optimization level — DONE

- New `OptimizationLevel.O2_NOINLINE` ("O2-noinline") in `models/project.py`,
  mapped to GCC flags `["-O2", "-fno-inline"]` via a new `opt_gcc_flags()` helper
  (`gcc.py` now uses it instead of `f"-{opt}"`, so multi-flag levels work).
  Inlining is the outlier optimization we want to toggle off even in optimized
  builds.
- **Removed `-fno-inline` from default `base_flags`** so plain `O2` is a genuine
  O2; inlining is now controlled solely by the opt level. `opt_level_labels`
  emits a `noinline` label for the variant.
- CLI `-O` choices come from the enum; added `--binary-limit`/`--binary-sample`.
  Tests added (`test_opt_level_gcc_flags`, round-trip, label test). All pass.

## Workstream B: 26 SAILR targets ported — DONE

All 26 sailr-eval packages ported to `projects/sailr/<name>.toml` (parallel
sub-agents, one per package + a consistency review). Conventions:
- Prefer official **release tarballs** (ship a generated `./configure`) over the
  sailr git+bootstrap recipes (avoids fragile gnulib network fetches).
- Every target compiles at `O0`, `O2`, `O2-noinline`; `base_flags =
  ["-g","-fno-builtin","-save-temps=obj"]`, `c_compiler="gcc"`.
- Each TOML's `labels` = `sailr` (origin) + a kind label + domain labels.

Category taxonomy (Workstream C — DONE):

| kind        | targets |
|-------------|---------|
| library     | gnutls, libacl, libbsd, libedit, libexpat, libselinux, zlib |
| cli-tool    | base-passwd, bzip2, coreutils, diffutils, dpkg, e2fsprogs, findutils, grep, gzip, iproute2, kmod, shadow, tar |
| daemon/server | cronie, openssh-portable, rsyslog, sysvinit |
| shell/interp  | bash, dash |

Domain labels span: compression, crypto, networking, parsing, text-processing,
filesystem, security, scheduling, logging, package-management, archiving,
terminal, init, search, system, kernel, compat, interpreter.

Build quirks: bzip2/libselinux/sysvinit hardcode CFLAGS → `make CFLAGS=... CC=...`;
libacl uses `source_dir "."` (non-recursive automake); rsyslog needs
libestr/libfastjson staged into `~/.local/sailr-deps` (no sudo); base-passwd uses
`make update-passwd` (default `all` runs a broken openjade docs build); iproute2 +
all GNU packages use `mirrors.kernel.org` (git.kernel.org snapshots 403, ftp.gnu.org
flaky).

## Workstream D: build verification — DONE (26/26 build)

`scripts/compile_all.py` compiles every (project, opt) in parallel into a
persistent `results/sailr_full/<opt>/<project>/compiled/` and reports per-target
ELF/.i counts. **All 26 targets build at all 3 opt levels**: ~229 (O0) / 233
(O2) / 235 (O2-noinline) ELF binaries each — ~697 total. Biggest: coreutils
(109/opt), shadow (40/opt), openssh (12/opt), gnutls (9/opt).

**Compile hang root-caused & fixed:** an initial 78-worker `fork`-based pool
deadlocked — late workers forked while the parent's pool-management thread held a
mutex, wedging them in `futex_wait` (downloads done, never extracted). Fix: the
driver scripts use the **`spawn`** multiprocessing context, and a modest worker
count (a 70-way simultaneous `configure` storm also contends badly).

## Workstream E: full benchmark run

Decompilers: **angr + ghidra** (IDA/binja unavailable on this machine). Metrics:
all three (GED, type_match, byte_match). Opt levels: O0 / O2 / O2-noinline.

Driver: `scripts/run_benchmark.py` (resilient — checkpoints decompile+evaluate
per project to `results/sailr_full/checkpoints/<project>.pkl`, so a multi-hour
run survives crashes and resumes). `scripts/decompile_one.py` decompiles one
(binary, decompiler) in a short-lived subprocess.

### Performance engineering (validation surfaced two scaling walls)

1. **angr's decompiler is ~15-20 s/function** (Ghidra is ~0.5 s/function +
   ~14 s JVM start). A trivial binary that Ghidra did in 14 s took angr >180 s.
   On a large binary angr never finishes.
2. **decbench decompiles ALL `.text` functions**, but a binary like `grep` has
   ~800 functions of which ~790 are bundled gnulib/system-header code that no
   metric meaningfully attributes to the project. Decompiling them is pure waste
   and makes angr hopeless.

Fixes (all behind the run driver / opt-in, core behavior unchanged by default):

- **DWARF source-function filter** (`project_source_functions`): decompile only
  functions whose DWARF `decl_file` is one of the project's own compiled source
  files (`source_dir`, e.g. grep's `src/*.c`) — exactly SAILR's "score the
  project's own code" intent. grep dropped 808 → 3/56/102 functions (O0/O2/
  O2-noinline; O2 inflation is `.constprop`/`.isra` clones). NOTE: the
  preprocessed `.i` is NOT a usable filter — it expands to ~5000 functions
  (every inlined header), so DWARF is the right signal.
- **Hard per-(binary,decompiler) timeout** (default 240 s) via killable
  subprocess (angr ignores in-process signals at 100 % native CPU).
- **Partial-result recovery**: `decompile_binary` pickles progress after each
  function, so a timeout-kill still yields the functions angr completed (turns
  angr from "empty on big binaries" into "partial coverage").
- **GED node cap** (`DECBENCH_GED_MAX_NODES`, default 60): exact graph-edit
  distance is super-polynomial; a few huge optimized CFGs took ~10 s each
  (grep O2 evaluate was 592 s). Oversized graphs fall back to a cheap structural
  size-delta. grep O2 evaluate: 592 s → 33 s.
- **Parallel source-CFG extraction** in `evaluate_project`, and the driver
  extracts source CFGs once and reuses them for both the filter and GED.

Net: grep (worst case, one large binary) went 1784 s → 701 s, and BOTH
decompilers now populate all three metrics (angr no longer mostly-empty).

### Results — full run complete (2026-06-08)

**26 targets × O0/O2/O2-noinline × {angr, ghidra} × {GED, type_match,
byte_match}.** 697 binary-results, **38,255 distinct functions**, ~7.6 h wall.
Artifacts: `results/sailr_full/{scoreboard.toml, function_results.json (23 MB),
report.html (11 MB, interactive — label/binary toggles, comparison matrix)}`.

Scoreboard (perfect-%, i.e. fraction of scored functions that are an exact match):

| metric      | angr  | ghidra | winner |
|-------------|-------|--------|--------|
| GED (structural)   | **24.3%** | 18.7% | angr |
| type_match         | 9.1%  | **11.8%** | ghidra |
| byte_match         | 0.6%  | **1.0%**  | ghidra |
| Overall (all 3)    | 0.0%  | 0.0%   | — (byte_match dominates) |

Coverage (functions scored — shows angr's partial coverage from timeouts):
angr scored 5.4 k GED / 10.8 k type / 16.3 k byte; ghidra scored 14.0 k / 31.6 k
/ 33.4 k — Ghidra ~2-2.5× angr's coverage because angr times out (with partial
recovery) on large binaries. Both still produce thousands of scored functions.

**The O2-noinline variant earns its place** — perfect-% by opt level:

| opt | dec | GED | type_match | byte_match |
|-----|-----|-----|-----------|-----------|
| O0  | angr   | 28.4% | 17.6% | 0.0% |
| O0  | ghidra | 19.0% | 17.6% | 0.0% |
| O2  | angr   | 13.2% | 2.0%  | 1.0% |
| O2  | ghidra | 11.9% | 4.6%  | 0.4% |
| O2-noinline | angr   | 27.5% | 5.7%  | 0.8% |
| O2-noinline | ghidra | 23.8% | 12.6% | 2.2% |

Key finding: **inlining is a dominant degrader.** Going O2 → O2-noinline (only
difference: `-fno-inline`) roughly *doubles* GED structural accuracy (ghidra
11.9% → 23.8%, angr 13.2% → 27.5%) and lifts type_match (ghidra 4.6% → 12.6%).
The benchmark now isolates that effect directly, which the original 2-level
(O0/O2) setup could not. angr leads on structural correctness (GED) at every opt
level — consistent with its SAILR-derived structuring — while Ghidra leads on
type and byte recovery and on coverage.

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

---

# DecBench v2 — Extensibility, Caching, Re-runability & Report (2026-06-25)

A second expansion focused on making the suite extensible, re-runnable, and
self-documenting. Built foundation-first (shared contracts locked by the lead),
then **fanned out four parallel agents** on disjoint file sets, then integrated.

## What shipped (all 10 goals)

1. **Website redesigned** (`rendering/html.py`) to the mahaloz.re terminal
   aesthetic: black `#000` / `#DBDBDB` gray, Source Code Pro mono, dashed rules,
   `max-width:850px` left column, Unix-path nav, bracketed dates, ASCII `[####--]`
   bars, hover-inversion. All prior interactivity (label/binary toggles, live
   recompute, comparison matrix, per-binary breakdown) preserved.
2. **Re-runability without recompiling** (`dataset.py` + `decbench dataset
   save/list/materialize`): content-addressed store of compiled binaries + `.i`
   sources; `materialize` lays the tree back out for `run --skip-compile`.
3. **Large-function subset** (`scoring/subset.py` + `decbench subset`): computes
   the size bell-curve and selects the upper tail (`mean+k·std` or percentile),
   emitting a manifest + `filter_function_data` — no binary copying. (The
   majority of functions are small; this surfaces the hard, large ones.)
4. **Plugin guide** (`docs/ADDING_A_DECOMPILER.md`): the `Decompiler` ABC
   contract, a minimal worked example, registration, multi-version, Docker, and
   testing.
5. **Raw decompiler interfaces — declib dropped** (`decompilers/raw/`):
   `angr`/`ghidra`/`ida`/`binja` now drive native APIs directly. `raw/common.py`
   centralises ELF/address bookkeeping. declib backends remain as `*-declib`.
6. **Multiple versions of a decompiler** (`decompilers/spec.py` + registry):
   identity is `name@version`; `ghidra@12.0` vs `ghidra@12.1` run as distinct
   columns. Per-version settings in `~/.config/decbench/decompilers.toml`.
7. **Two report views** (`scoring/report_extras.py` + html.py): **Hardest
   Functions** (hall of shame of worst-scoring funcs with their decompiled code)
   and **Historical** (pure-SVG line charts per metric across versions/time,
   driven by the two real Ghidra versions).
8. **Metric caching** (`caching.py`): content-addressed; each metric's
   `compute_for_function` keys on its determining inputs (GED→CFG structures,
   type_match→vars+DWARF+shift, byte_match→code+orig bytes). Re-seen
   (decompiled, source) pairs skip recomputation. `DECBENCH_NO_CACHE` disables.
9. **Reko backend** (`dockerized.py` + `docker/reko.Dockerfile`).
10. **RetDec + r2dec** (`dockerized.py` + `docker/{retdec,r2dec}.Dockerfile`);
    r2dec runs **natively** via radare2.

## Environment updates (vs the v1 notes)
- **IDA Pro 9.2 idalib WORKS here** (`/home/mahaloz/ctf/tools/idapro_9.2`,
  license present) — the old "only unusable IDA 8.0" note is obsolete.
- **Ghidra 12.0** installed alongside 12.1 (`/home/mahaloz/bin/ghidra_12.0`) for
  multi-version benchmarking; config in `~/.config/decbench/decompilers.toml`.
- **Docker works** (no sudo) — used for RetDec/Reko images (not pre-built).
- 7 backends available: `angr, ghidra, ida, r2dec, angr-declib, ghidra-declib,
  ida-declib` (`binja`/`binja-declib` need Binary Ninja; `retdec`/`reko` need
  their images built).

## Validation (`scripts/run_small.py`, gzip/O0, 4 functions)
Ran `angr, ida, ghidra@12.0, ghidra@12.1` (each in an isolated subprocess —
required: pyghidra binds one JVM per process, so two Ghidra versions can't share
one). Result: all three metrics scored for all four; GED ghidra@12.x 75% / ida
66.7% / angr 50%; type_match 100% for ghidra+ida, 50% angr. **22 hardest
entries** and **2 history points** (ghidra 12.0/12.1) embedded in the report;
**metric cache 11 hits / 28 misses** — the hits are real cross-version reuse
(12.0 and 12.1 emit identical C for some functions, so the metric is reused).

## Known limitations
- RetDec/Reko Docker images are lint-clean but not pre-built here (slow builds);
  `is_available()` is False until `decbench decompiler-build <name>`.
- r2dec uses radare2's built-in `pdc` (the r2dec plugin can't build without dev
  headers/sudo); the Docker image builds radare2 from source for the real plugin.
- `binja` raw backend is coded but untestable (Binary Ninja not installed).
- Line mappings are best-effort: angr/Ghidra populate them; IDA/binja return
  `[]` (GED degrades gracefully). Dockerized backends emit `variables=[]`.

## Test status
- **93 passed, 2 skipped** (the 2 skips are the RetDec/Reko docker smoke tests
  that skip when images are absent). New tests: caching/dataset/subset (17),
  dockerized decompilers (15). `ruff check` on touched files: only minor
  stylistic remainders (line-length/raise-from), consistent with baseline.

## Report follow-up: dataset selector (replaces granular toggles)

The report's many label-chip + per-binary toggles were collapsed into a single
**dataset selector** with four curated views (`scoring/datasets.py`,
`assign_datasets`):
- **full** — everything (O0 + O2 + O2-noinline; per-opt double-count ok).
- **hard** — optimized, no inlining (O2-noinline), large functions only.
- **hard-inlined** — like hard but with inlining (O2), large only.
- **tiny** — ~100 functions evenly sampled across inlined(O2)/optimized
  (O2-noinline)/unoptimized(O0)/large, and spread evenly across projects.

"Large" = upper tail of the size bell curve (mean+1σ over decompiled line
counts), falling back to the `large` label when sizes are absent. Membership is
tagged server-side per function (`FunctionRecord.datasets`); the report shows
one selector and recomputes the matrix/per-binary/rankings over the chosen view.
Verified on the real 38,255-function corpus: full=38255, hard=1317,
hard-inlined=1678, tiny=100 (spanning all 26 projects). Tests: 98 passed, 2
skipped (+5 dataset-preset tests). Report: results/sailr_full/report_v2.html.

## tiny sampling: seeded + even, one-per-binary; per-binary hover

- The `tiny` sample is now a **seeded random** selection (reproducible across
  runs; seed via `assign_datasets(seed=...)` or `DECBENCH_TINY_SEED`, default
  `DEFAULT_TINY_SEED=1337`), so the chosen targets are stable but changeable.
- Even on two axes: round-robin across projects AND **at most one function per
  binary** (project,opt,binary) while distinct binaries last — a second pass
  relaxes the binary rule only if there are too few binaries to fill the quota.
  On the full corpus, `tiny` = 100 functions from 100 distinct binaries across
  all 26 projects.
- Report: hovering a per-binary breakdown row now shows the function name(s)
  that binary contributes to the current dataset (`tr.title`; for `tiny` that is
  exactly one function). Tests: 103 passed, 2 skipped (+5 new dataset tests).

---

# CPS / drone / RTOS dataset — cross-compiled embedded targets (2026-06-26)

Added a new category of benchmark targets: drone / cyber-physical / RTOS
firmware, each **cross-compiled for specific embedded hardware** (real MCU /
board), as `projects/cps/*.toml`. Built foundation-first then fanned out three
agents that each verified builds inside an ARM-toolchain Docker image
(`decbench-cps-toolchain`) using decbench's exact compile contract.

## 11 targets — all VERIFIED (ARM ELF; .i / -g where the build allows)

| target | what | hardware (MCU/board) | toolchain | opts | .i | -g |
|---|---|---|---|---|---|---|
| libopencm3 | Cortex-M firmware lib + examples | STM32F4 / Cortex-M4 | arm-none-eabi | O0/O2/O2-ni | 125 | yes |
| freertos | RTOS kernel demo | MPS2 / Cortex-M3 | arm-none-eabi | O0/O2/O2-ni | 41 | yes |
| chibios | RTOS demo | STM32F407 / Cortex-M4 | arm-none-eabi | O0/O2/O2-ni | 74 | yes |
| nuttx | RTOS (nsh) | stm32f4discovery / Cortex-M4 | arm-none-eabi | O0/O2/O2-ni | 1093 | yes |
| riot-os | IoT RTOS example | nucleo-f401re / Cortex-M4 | arm-none-eabi | O0/O2/O2-ni | 43 | yes |
| betaflight | drone flight controller | STM32F405 / Cortex-M4F | arm-none-eabi | O0/O2/O2-ni | 416 | yes |
| cleanflight | drone flight controller | DALRCF405 / Cortex-M4F | arm-none-eabi | O0/O2/O2-ni | 257 | yes |
| crazyflie | nano-drone firmware | cf2 STM32F405 / Cortex-M4F | arm-none-eabi | O0/O2/O2-ni | 532 | yes |
| ardupilot | drone autopilot (ChibiOS) | MatekF405 / Cortex-M4F | arm-none-eabi | O2 | — | yes |
| px4-autopilot | drone autopilot (NuttX) | px4_fmu-v5 / Cortex-M7F | arm-none-eabi | O2 | — | yes |
| u-boot | embedded bootloader | vexpress-ca9x4 / Cortex-A9 (ARMv7) | arm-linux-gnueabihf | O2/O2-ni | 253 | yes |

- ardupilot/px4 use waf/cmake that pick the toolchain by board, so decbench's
  CFLAGS don't reach them → single realistic opt level, no `.i` (ELF + DWARF
  present). u-boot drops O0 (driver-model DCE needs ≥O1). Everything else builds
  all three opt levels with `.i` + `-g`.
- byte_match will be ~0 for these (recompiles with host x86 gcc vs ARM bytes);
  GED (needs `.i`) and type_match (needs DWARF) are the usable metrics, plus
  structural decompilation by angr/Ghidra (both handle ARM/Thumb).

## How they cross-compile through decbench
- `c_compiler = "arm-none-eabi-gcc"` (bare-metal Cortex-M) or
  `"arm-linux-gnueabihf-gcc"` (embedded-Linux ARM, u-boot). The project's own
  board/target build supplies the `-mcpu=cortex-mX -mthumb -mfloat-abi=...` arch
  flags; decbench appends `-g -save-temps=obj` + the opt level via each
  project's flag-injection hook (EXTRA_FLAGS / USE_OPT / KCFLAGS / EXTRAFLAGS /
  KCFLAGS / `make CFLAGS=` as appropriate — see each TOML). Submodules via
  `post_download_cmds`.
- **New `target_arch` filter** (`CompilationConfig.target_arch`): cross-compiled
  builds produce incidental **host tools** (e.g. u-boot's x86 `mkimage`);
  `target_arch = "arm"` makes `compile_project` collect only the ARM hardware
  binaries. Verified: u-boot went from 21 collected (16 x86 + 5 ARM) to just the
  ARM binaries.

## Toolchain (Dockerfile)
Added both cross toolchains (gcc-arm-none-eabi + newlib/binutils; gcc-arm-linux-
gnueabihf) plus cmake/flex/dtc/file/libtool-bin, the U-Boot host-tool libs
(libssl-dev, uuid-dev, libgnutls28-dev), python-is-python3, and the ArduPilot
(waf) / PX4 (cmake) Python helpers (empy 3.3.4, pyserial, future, jsonschema,
pyyaml, lxml, cerberus, jinja2, numpy, …).

## Validation
`scripts/cps_compile_smoke.py` drives decbench's real `compile_project` and
reports collected ELF arch + `.i` counts. Confirmed end-to-end through decbench:
- riot-os (arm-none-eabi): 1 ARM ELF + 38 `.i` → PASS.
- u-boot (arm-linux-gnueabihf): ARM `u-boot` + EFI apps + 253 `.i`, host x86
  tools filtered out by `target_arch` → PASS.
Categorized via TOML `labels` (cps + kind + domain + bare-metal/embedded-linux +
MCU/board). Tests: 103 passed, 2 skipped.

## CPS scoring — preliminary measurement (2026-06-27)

The CPS/ARM targets are **not in any published scoreboard yet** — the big
`sailr_full` run was x86-only, and these ARM binaries had never been
decompiled/evaluated. A small sample run (decompile+evaluate of one compiled
target) measured the impact. Sample: **riot-os** (STM32F401 / Cortex-M4, O2),
angr + ghidra, first ~11 source∩binary functions.

| corpus | dec | GED | type_match | byte_match | Overall |
|---|---|---|---|---|---|
| sailr (x86, 38,255 fns) | angr | 24.3% | 9.1% | 0.6% | 0.0% |
| sailr (x86, 38,255 fns) | ghidra | 18.7% | 11.8% | 1.0% | 0.0% |
| riot-os (ARM, 11 fns) | angr | 54.5% | **0.0%** | 0.0% | 0.0% |
| riot-os (ARM, 11 fns) | ghidra | 45.5% | **42.9%** | 0.0% | 0.0% |

Findings (directional — tiny, libc-biased sample, not a corpus measurement):
- **byte_match -> ~0** for every decompiler on ARM: it recompiles the decompiled
  C with the host **x86** gcc and compares to the **ARM** original bytes, so it
  cannot match cross-arch. Architectural, not a decompiler failure.
- **Overall -> ~0**, unchanged: with byte_match unable to be perfect, no CPS
  function is perfect-on-all-3 — but Overall is already ~0 on x86 too.
- **GED is arch-portable** and works on ARM for both decompilers (the high
  numbers here are inflated by the libc/init stub functions the sampler picked).
- **type_match splits hard by decompiler on ARM**: Ghidra recovers ARM stack
  vars/args well (42.9%), angr recovered ~none (0.0%) — its Cortex-M variable
  recovery is weak (CLE logs "Unknown reloc 40 on ARMCortexM" + "variable offset
  with stride shorter than the primitive type"). So adding CPS would **widen
  Ghidra's type-recovery lead** over angr.
- **Coverage skew**: angr is ~15-20 s/fn and CPS firmware is large (px4 ELF is
  46 MB) -> angr will mostly time out on CPS; Ghidra has far better coverage.
- Pipeline notes: Ghidra's raw backend writes its project file next to the
  binary, so it needs a writable dir (it failed only on the root-owned Docker
  smoke output; normal `decbench run` output dirs are user-owned, so this is a
  non-issue in practice). angr loads Cortex-M with relocation warnings but still
  decompiles.

Aggregate effect if CPS is folded into the `full` dataset: byte_match average
drops (more zeros), Overall stays ~0, type_match widens the Ghidra>angr gap, GED
shifts toward the ARM values, and the `tiny`/`hard` presets start sampling CPS
binaries. A definitive CPS scoreboard needs a full decompile+evaluate run across
all 11 targets (compile in Docker -> decompile locally with angr/Ghidra ->
evaluate); GED + type_match are the meaningful metrics there (byte_match ~0).

## CPS: C++ targets disabled (2026-06-27)

Two of the 11 CPS targets are **C++** — **ArduPilot** (~61% C++) and **PX4**
(~50% C++); the other 9 are C (verified via GitHub language stats). decbench has
no C++ support yet (GED's source-CFG extractor / pyjoern is C-oriented — these
two produce no `.i` and can't be scored on GED), so they have been **disabled**:
moved to `projects/cps/disabled/` so they are excluded from every
`projects/cps/*.toml` evaluation glob, with a README and an in-file banner. Their
build recipes remain verified-working; re-enable by moving the TOML back up to
`projects/cps/`. Active CPS dataset is now **9 C targets** (libopencm3, freertos,
chibios, nuttx, riot-os, betaflight, cleanflight, crazyflie, u-boot).

---

# Malware dataset — REAL malware decompiler targets (2026-06-27)

Added REAL malware (C only, from theZoo) as decompiler benchmark targets in
`projects/malware/*.toml`. These are **COMPILED, NEVER EXECUTED**, and only
inside the container — malware analysis is a core *defensive* use of decompilers.

## Reality of theZoo's C malware
theZoo `Source/{Original,Reversed}` (97 samples) is mostly C++/Windows (26),
scripts/asm/VB/Android (~35), or unidentified. Only ~10 are C, and only ~3 of
those are Linux/POSIX (all Mirai). So "compile like everyone else" (gcc→ELF)
can't reach 10 from theZoo; the user opted to cross-compile the Windows‑C
samples with **MinGW → PE** to get a useful set.

## Final set: 6 distinct C malware (of ~12 candidates compiled-tested)
| name | family | OS | format | compiler |
|---|---|---|---|---|
| mirai | IoT botnet (Mirai) | linux | ELF | gcc |
| mirai-win | Mirai variant ("eragon") | linux | ELF | gcc |
| mydoom | email worm (MyDoom.A) | windows | PE32 | i686 MinGW |
| x0r-usb | USB/IRC worm | windows | PE32 | i686 MinGW |
| minipig | PE infector | windows | PE32 | i686 MinGW |
| dexter | point-of-sale scraper | windows | PE32 DLL | i686 MinGW |

Each builds at O0/O2/O2-noinline with `.i` + (ELF) DWARF.

**Honestly failed (no TOML)** — genuine source/platform issues, not given up on
lightly: `remhead` (bundled NT headers structurally conflict with modern MinGW),
`dokan` (modern-gcc source incompatibilities), `rubilyn` (macOS-kernel rootkit,
needs XNU headers). `mirai-2016` was dropped (byte-identical to `mirai`/IoT.Mirai
— a true duplicate). The `Reversed` dir's Win32 samples are assembly. C++ is
excluded per "C only". So 6 is the real ceiling of theZoo's compilable C malware.

## Safety design (decbench foundation)
- `ProjectConfig.is_malware` + a guard in `compile_project` that **refuses to
  build on a bare host** (requires `/.dockerenv` / `DECBENCH_IN_CONTAINER`, or an
  explicit `DECBENCH_ALLOW_MALWARE=1` override).
- `ProjectConfig.download_cmd`: fetches+extracts just the one theZoo zip
  (password `infected`) — no full theZoo clone, no malware in the repo.
- `make_cmd` is a **direct gcc/MinGW compile** of the .c files (decbench's
  `$CC`/`$CFLAGS`), NOT the malware's own Makefile — avoids build-time payloads.
- PE-binary collection added to `compilers/gcc.py` (MZ/PE detection + PE machine),
  so MinGW output is collected like ELF.
- Dockerfile ships `gcc-mingw-w64` + `unzip`. `projects/malware/README.md` has
  the loud DO-NOT-EXECUTE policy. Compiled binaries land only in gitignored
  `results/` and are never run.
- All verify-compilation was done in ephemeral `--rm` containers, no host mounts;
  no binary was ever executed.

## Metric coverage
GED (source CFG from `.i`) + structural decompilation (angr/Ghidra load ELF and
PE) apply to all. For the PE targets, **byte_match and type_match don't apply**
yet (both read ELF/DWARF via pyelftools). The Mirai/ELF targets can score on all
three.

## Validation
decbench's real `compile_project` on `mydoom` (in-container): guard passed,
`download_cmd` fetched theZoo, MinGW built it, the pipeline **collected the PE32
binary + 10 `.i` files**. Tests: still green.
