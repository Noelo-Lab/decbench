# Benchmarking — environment, corpus, and large runs

Everything about *running* DecBench on this machine: what is installed where,
what the benchmark corpus contains, the resilient run drivers, and the
overlay → finalize flow that produces the published numbers. Metric internals
live in [metrics.md](metrics.md); backend internals and how to add a
decompiler in [decompilers.md](decompilers.md).

## Machine environment

- Use the `decbench` virtualenv at `/home/mahaloz/.virtualenvs/decbench`
  (Python 3.14; decbench installed editable). Activate with
  `source /home/mahaloz/.virtualenvs/decbench/bin/activate`. (The package
  itself supports >=3.10 per pyproject.toml; only the dewolf sidecar venv
  still runs 3.10.)
- Docker works here (no sudo needed); used for the RetDec/Reko/r2dec images
  and the `decbench-compile` cross-compile image.
- `pygraphviz` builds against the system `libgraphviz-dev` (installed).
- `declib` (4.0.1, PyPI) is still installed and the `*-declib` backends still
  use it, but the **canonical** `angr`/`ghidra`/`ida`/`binja` backends are now
  native (declib-free) implementations under `decbench/decompilers/raw/`.

### Decompiler backends available and working

Verified via the raw, declib-free interfaces; `decbench list-decompilers`
shows live availability. The core benchmark set is **angr, ghidra, ida,
binja** (+ kuna in the full run); **r2dec** and **dewolf** are the newest
additions. (The former angr-variant backend that forced a non-default
structurer was fully retired 2026-07-23; see CHANGELOG.md.)

- **angr** — pip.
- **Ghidra 12.1 and 12.0** — `/home/mahaloz/bin/ghidra_12.{1,0}`, via
  pyghidra; export `GHIDRA_INSTALL_DIR` for the unversioned default.
- **IDA Pro 9.2 idalib** — at `/home/mahaloz/ctf/tools/idapro_9.2`.
- **Binary Ninja 5.3** (core 5.3.9757) — install at
  `/home/mahaloz/ctf/tools/binja/binaryninja`; added to the venv via a
  `binaryninja.pth` in site-packages; needs a license at
  `~/.binaryninja/license.dat` — a Commercial/Ultimate license is required
  for headless use, and it must cover the installed version.
- **r2dec** — radare2; the benchmark path is the REAL r2dec plugin via the
  `decbench/r2dec` Docker image — native `pdc` is a fallback whose asm-like
  output yields no Joern CFG, so `pdd` is required for GED.
- **dewolf** — fkie-cad/dewolf, a Binary-Ninja research decompiler run OUT OF
  PROCESS in its own py3.10 venv at `/home/mahaloz/.virtualenvs/dewolf` with
  the repo at `/home/mahaloz/ctf/tools/dewolf`; see `raw/dewolf_raw.py` +
  `raw/dewolf_driver.py`, configured under `[dewolf.versions.default]`.
- **RetDec / Reko** — Dockerized (`docker/`); their images are NOT currently
  built on this machine (`list-decompilers` shows N) — build one with
  `decbench decompiler-build <name>` first.
- **codex / claude-code / kimi-code** — LLM coding-agent backends,
  sample-set-only; see [decompilers.md](decompilers.md). codex and
  claude-code are logged in and available; kimi-code shows N until a Kimi
  OAuth login exists on this machine.

### Five Ghidra versions (multi-version / historical benchmarking)

`~/.config/decbench/decompilers.toml` configures `ghidra@12.1`, `ghidra@12.0`
(in `/home/mahaloz/bin/ghidra_12.{1,0}`), plus the historical `ghidra@11.4`
(11.4.3), `ghidra@11.0` (11.0.3), and `ghidra@10.4` (unzipped under
`/home/mahaloz/bin/ghidra_*_PUBLIC`). Run them as distinct specs
(`-d ghidra@11.0 ...`).

- They **MUST run in separate processes** — pyghidra binds a single JVM to one
  install per process, so `ghidra@12.0` and `ghidra@12.1` cannot both run in
  one process. The run drivers already isolate them (`decompile_one.py`
  subprocess per task); `scripts/run_small.py` validates this end-to-end.
- Launch dispatch is version-aware (`raw/ghidra_raw.py`): pip `pyghidra`
  (>=12.0), the install's OWN bundled PyGhidra (11.2–11.x), or the predecessor
  `pyhidra` (<11.2). Each version's JDK comes from a per-version `java_home`
  in the config (<=11.1 → JDK 17, >=11.2 → JDK 21).
- `scripts/ingest_history.py <versioned-run> <target-tree>` merges a versioned
  run into a tree's history points (stored in `function_results.json` —
  unshipped since the Historical view was removed 2026-07-22).

### pyjoern / Joern (GED's engine)

`pyjoern` bundles a ~1.9 GB Joern under site-packages and powers the GED
metric. Gotcha: the wheel can ship a MISMATCHED joern-cli bundle (1.2.18 jars
under a 4.x wrapper) which silently breaks `parse_source` → GED scores
nothing. Fix: drop the matching Joern **v4.0.150** `joern-cli` into
`site-packages/pyjoern/bin/joern-cli/` (its zip SHA-512 must equal
`pyjoern.__init__.JOERN_ZIP_HASH`). Re-apply after any pyjoern reinstall.

## The benchmark corpus

Targets are project TOMLs under `projects/`; a "full run" spans all of
`projects/{sailr,cps,malware,cpp}/*.toml` (both drivers gather them via
`gather_tomls()`; `cps/disabled/` and `cpp/disabled/` excluded). Everything
except `projects/cpp/` is C — and **every C++ target ships disabled**, so a
default full run is C-only.

- **sailr** — 26 sailr-eval Debian packages in `projects/sailr/*.toml`, each
  built at O0 / O2 / O2-noinline, labeled by kind + domain. Compiles on the
  host (x86).
- **cps** — 9 active CPS/drone/RTOS firmware targets in `projects/cps/*.toml`,
  each CROSS-COMPILED for specific embedded hardware (Cortex-M/-A):
  libopencm3, FreeRTOS, ChibiOS, NuttX, RIOT-OS, Betaflight, Cleanflight,
  Crazyflie, U-Boot. They set `c_compiler=arm-none-eabi-gcc` (bare metal) or
  `arm-linux-gnueabihf-gcc` (embedded Linux) and `target_arch="arm"` so only
  the hardware binaries are collected (not incidental x86 host tools). The
  Docker image ships both cross toolchains + their build deps; verify a build
  with `scripts/cps_compile_smoke.py` inside the image. angr/Ghidra decompile
  ARM; byte_match abstains for ARM on hosts without the arm-none-eabi
  toolchain — GED/type_match carry these targets. The two C++ autopilots
  (ArduPilot, PX4) are still DISABLED in `projects/cps/disabled/`; their
  recipes are verified-working and re-enable by moving the TOML back up to
  `projects/cps/`, but neither has been run through the C++ path below.
- **malware** — REAL MALWARE targets in `projects/malware/*.toml` (C, from
  theZoo): mirai (ELF/gcc), mydoom, x0r-usb, minipig, dexter (PE/MinGW).
  (mirai-win was removed 2026-07-23: theZoo's "Win32.Mirai" is actually
  Linux/ELF sources — it duplicated mirai and implied Windows coverage it
  didn't provide.) These are **COMPILED, NEVER EXECUTED, and ONLY inside the
  container**: each sets `is_malware=true` and `compile_project` REFUSES to
  build them on a bare host (needs `/.dockerenv` or
  `DECBENCH_ALLOW_MALWARE=1`). `download_cmd` fetches+extracts (password
  'infected') just the one theZoo zip; `make_cmd` is a DIRECT gcc/mingw
  compile (not the malware's Makefile). PE binaries are collected like ELF
  (`compilers/gcc.py` PE detection). All three metrics work on PE via
  `utils/binfmt.py` (byte_match needs the MinGW toolchain, else it abstains).
  See `projects/malware/README.md` (DO NOT EXECUTE). Binaries never leave
  `results/`.
- **cpp** — the C++ targets. **Experimental, and disabled by default**: the
  only target, **leveldb** (Google's embedded key-value store, CMake, x86 host
  build), sits in `projects/cpp/disabled/` and so matches no
  `projects/cpp/*.toml` glob. The support code is always active; only the
  target list is gated. See `projects/cpp/disabled/README.md` to enable one,
  and read [C++ targets](#c-targets) before using any C++ number.

### C++ targets

C++ works end-to-end as of `projects/cpp/disabled/leveldb.toml` (experimental,
and disabled by default — see `projects/cpp/disabled/README.md`); the mechanics live in
[metrics.md](metrics.md#preprocessed-iii-files-are-required--source-cfgs-come-exclusively-from-them).
Three things are worth knowing before reading a C++ number:

- **No demangler is involved anywhere.** DWARF `DW_AT_name` for
  `leveldb::DBImpl::Get` is `"Get"`, and Joern's C++ frontend keys on the short
  name too, so both sides of the match already speak unqualified names. Mangled
  `_ZN...` never appears.
- **Same-name collisions make a C++ target's absolute GED incomparable to a C
  project's.** Because matching is by unqualified name, leveldb's 7-8
  same-named methods per name (`Next`, `Seek`, `SeekToFirst`, `Name` — one per
  iterator class) all collapse onto whichever body won the per-name reduction.
  Rank C++ targets against each other; do not read leveldb's GED next to
  grep's. Qualified-name keying is the fix and is not implemented.
- **Not publishable to the dataset yet.** The publish/dataset paths still glob
  only `*.i`, so a C++ project's source CFGs never make it into the exported
  tree (see metrics.md for the file list).

CMake-based C++ TOMLs have two traps worth copying from leveldb's: leave
`CMAKE_BUILD_TYPE` **empty** (a named type appends its own `-O` flag AFTER
`CMAKE_CXX_FLAGS` and silently overrides the level being measured), and set
`BUILD_SHARED_LIBS=ON` (a static `.a` is not a linked binary, so the collector
skips it and the library under test never gets decompiled).

### Optimization levels

`OptimizationLevel` (`decbench/models/project.py`) maps each level to GCC
flags via `opt_gcc_flags()` — use that, never `f"-{opt}"`. Levels:
`O0`/`O1`/`O2`/`O3`/`Os`/`Oz` plus **`O2-noinline`** (= `-O2 -fno-inline`), an
optimized build with inlining (an outlier optimization that destroys function
boundaries) specifically disabled. Plain `O2` is now a *genuine* O2:
`-fno-inline` was removed from the default `base_flags`, so inlining is
controlled solely by the level. `opt_level_labels` adds a `noinline` label for
the noinline variants.

### Project TOML gotchas

- Local (`remote_type = "local"`) projects build **in-place**; use
  `pre_make_cmds = ["make clean"]` and avoid compiling multiple opt levels in
  parallel for the same local project (`-j 1`), or stale/raced artifacts
  result.
- Project source URLs: prefer release tarballs over git+bootstrap;
  `ftp.gnu.org` is flaky here, so GNU packages use the
  `mirrors.kernel.org/gnu/` mirror. Makefiles that hardcode CFLAGS need
  `make_cmd = 'make CFLAGS="$CFLAGS" CC="$CC"'`.
- `tests/example_project/`'s Makefile uses `CFLAGS ?=` so the pipeline's env
  CFLAGS — which carry the opt level — take effect; new local projects should
  do the same.
- Projects support `labels` and `binary_labels` TOML fields — they feed label
  derivation (`scoring/labels.py`; see docs/site.md) and the site's category
  tables.

## CLI runs, caching, and reusable datasets

```bash
decbench run project.toml -O O0 -O O2 -O O2-noinline -d angr -d ghidra  # full pipeline
decbench run project.toml -d ghidra@12.0 -d ghidra@12.1  # multiple versions
decbench list-decompilers           # show available decompilers
decbench list-metrics               # show available metrics
decbench evaluate binary.elf        # evaluate single binary
decbench report scoreboard.toml     # HTML report (interactive if
                                    # function_results.json sits next to it)
```

- **Caching is automatic** (content-addressed, `decbench/caching.py`);
  `DECBENCH_NO_CACHE=1` disables it, `DECBENCH_CACHE_DIR` moves the root.
  Details + the `cache_version` rule: [metrics.md](metrics.md#metric-caching).
- **Binary datasets** (`decbench/dataset.py`): content-addresses compiled
  binaries + `.i` sources into a reusable store so a benchmark re-runs
  **without recompiling** (`decbench dataset save/list/materialize`) —
  `decbench dataset save results/sailr_full sailr`, then
  `decbench dataset materialize sailr results/reuse` and
  `decbench run --skip-compile`.
- **Large-function subsets** (`decbench/scoring/subset.py`): find the
  upper tail of the size bell curve (`mean + k·std` or a percentile) and emit
  a manifest to evaluate/report on just the hard, large functions — no binary
  copying: `decbench subset results/sailr_full/function_results.json`.

## Large runs: the `scripts/` drivers

Prefer the resilient drivers in `scripts/` over a single `decbench run` — they
use the `spawn` multiprocessing context (the default `fork` DEADLOCKS when
workers are forked after angr's threads start) and checkpoint per project so a
multi-hour run survives crashes:

```bash
GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/compile_all.py results/sailr_full 16   # compile all (16 workers)
DECBENCH_WORKERS=40 GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/run_benchmark.py results/sailr_full     # decompile+evaluate+report
```

`run_benchmark.py` knobs (env):

- `DECBENCH_DECOMPILERS` (default `angr,ghidra`)
- `DECBENCH_DECOMPILE_TIMEOUT` (s, default 300)
- `DECBENCH_GED_MAX_NODES` (60; read in `metrics/ged.py`, takes effect during
  runs)
- `DECBENCH_OPT_LEVELS` (comma list, e.g. `"O0"` to narrow the run)
- `DECBENCH_METRICS` (comma list, e.g. `"ged"` for a GED-only run)

### Per-decompiler wall-clock budgets

`DECOMPILER_TIMEOUT` in `scripts/run_benchmark.py` overrides
`DECBENCH_DECOMPILE_TIMEOUT` per backend (each with its own
`DECBENCH_<NAME>_TIMEOUT` env override). The fairness principle: every backend
gets enough time to finish the largest source-function set, so a slow-but-working
one is not truncated and counted as thousands of failures while a faster one
finishes. Small binaries finish in seconds, so these defaults only bite the ~10
big targets (bash, openssh, coreutils, the large ARM firmware).

| Backend | Default | Why |
| --- | --- | --- |
| `angr` | 3600 s | ~15-20 s/function; a big binary legitimately needs ~1 h. |
| `ghidra` / `binja` / `r2dec` | 1800 s | Fast per function, but a few large binaries overrun 300 s. r2dec's `aaa` analysis alone can run minutes. |
| `kuna` | 900 s | Emits its JSON only at the very end, so a kill yields ZERO functions; needs a budget above its slowest binary (~450 s on bash). Its per-FUNCTION guard is `--max-fn-seconds`, passed by the backend. |
| `dewolf` | 1200 s | A z3/sympy simplification pipeline that blows up per function. Capped lower than angr because the cap bounds *hangs*, not a slow-but-progressing decompile. |
| `codex` / `claude-code` / `kimi-code` | 3600 s | One agentic CLI call per function (~minutes). The backend checkpoints after each function, so a large budget bounds a stuck call while still crediting finished ones. |

Resume MERGES per project AND per decompiler:
`DECBENCH_DECOMPILERS=r2dec python scripts/run_benchmark.py results/full_run`
ADDS r2dec (or dewolf) to every project's checkpoint without re-running the
others, then regenerates `function_results.json` with the new column. Restart
resumes from per-project checkpoints; `... results/sailr_full -- grep` limits
to named projects. Single project: `scripts/decompile_one.py`.

Multi-version Ghidra example (GED-only over O0, five versions):

```bash
DECBENCH_DECOMPILERS=ghidra@12.1,ghidra@12.0,ghidra@11.4,ghidra@11.0,ghidra@10.4 \
DECBENCH_OPT_LEVELS=O0 DECBENCH_METRICS=ged \
python scripts/run_benchmark.py results/ghidra_history -- <sailr stems>
# then fold into a tree's history points:
python scripts/ingest_history.py results/ghidra_history results/full_run
```

Quick end-to-end smoke (raw backends + 2 Ghidra versions + caching + report):

```bash
DECBENCH_SMALL_DECOMPILERS="angr,ida,ghidra@12.0,ghidra@12.1" python scripts/run_small.py
```

### Why the run driver isn't just `decbench run`

Key scaling facts: angr's decompiler is ~15-20 s/function (Ghidra
~0.5 s/func) and decbench decompiles *all* `.text` functions, ~99% of which
are bundled gnulib in some binaries. So the driver (a) filters decompilation
to the project's own source functions via DWARF `decl_file`
(`project_source_functions`), (b) imposes a hard per-binary timeout via
killable subprocess, (c) recovers partial results on timeout
(`decompile_binary(progress_path=...)` pickles after each function), and
(d) caps exact GED to CFGs ≤ `DECBENCH_GED_MAX_NODES` nodes
(super-polynomial; a few huge optimized CFGs otherwise dominate). These make
angr tractable and bound the run; default in-process `decbench run` does none
of them.

Other driver facts:

- Any new parallel driver must set `spawn`/`forkserver`, never `fork`: the
  main process imports angr (which starts threads), and forking workers
  afterward deadlocks them on a mutex held at fork time (symptom: workers
  wedged in `futex_wait`, downloads done but never extracted). Also avoid 70+
  simultaneous autotools builds — the `configure` storm contends badly; ~16
  workers is plenty.
- `scripts/decompile_one.py` must `import decbench.decompilers` (the whole
  package) to register raw+declib+dockerized — importing just `declib_dec`
  would miss the canonical names.
- `DecompilerConfig.function_timeout_seconds` is advisory: declib exposes no
  per-function decompile timeout.
- angr vendors ailment as `angr.ailment`; the standalone `ailment` package is
  a different module — `isinstance` checks against the wrong one silently fail
  (this bit declib's line mapping once; fixed in ~/github/declib).
- The in-process pipeline (`pipeline/decompile.py`) also runs each decompile
  task in a fresh process via `max_tasks_per_child=1`, so JVM/idalib state
  never leaks between tasks.

## The FULL run

A **full run = EVERY project AND EVERY supported decompiler**: all of
`projects/{sailr,cps,malware}/*.toml` decompiled by all backends available on
this machine — angr, ghidra, ida, binja, kuna, r2dec, and dewolf (+ the LLM
sample-set-only backends on their slice). If a new project or decompiler is
added, "full run" includes it too; scope down only for a deliberate partial
pass. (sailr x86 + cps ARM + malware ARM/PE.)

sailr compiles on the host; cps/malware need the cross/mingw toolchains so
they compile INSIDE the slim `decbench-compile` image
(`docker/compile.Dockerfile` — ARM + mingw + decbench's light compile deps;
the host has no cross/mingw gcc). Decompilation runs on the HOST for all of
them (the raw backends + executor discover ELF *and* PE; PE malware decompiles
via ghidra/ida/binja/angr). Steps:

```bash
# 1) host-compile sailr:
python scripts/compile_all.py results/full_run 20
# 2) one-time image build:
docker build -f docker/compile.Dockerfile -t decbench-compile .
# 3) docker-compile cps+malware INTO the same tree (run as host user;
#    /.dockerenv satisfies the is_malware guard):
docker run --rm -v "$PWD":/workspace -w /workspace -e PYTHONPATH=/workspace \
  -e HOME=/tmp --user "$(id -u):$(id -g)" decbench-compile \
  python3 scripts/compile_all.py results/full_run 8 <cps+malware stems...>
# 4) one decompile+evaluate+report pass over everything (resumes per-project):
DECBENCH_WORKERS=40 \
  DECBENCH_DECOMPILERS=angr,ghidra,ida,binja,kuna,r2dec,dewolf \
  GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
  python scripts/run_benchmark.py results/full_run
```

Notes:

- dewolf is slow + BN-based; for it, prefer several concurrent instances on
  disjoint project groups + `DECBENCH_DEWOLF_SHARDS` to saturate cores — see
  the dewolf backend notes. r2dec runs via its Docker image. Resume is
  per-project AND per-decompiler, so a full run can be assembled
  decompiler-by-decompiler.
- byte_match ABSTAINS (no result, not 0) for ARM/PE on the host (no
  cross/mingw recompiler) — GED + type_match carry cps/malware. The summary
  column is Union (perfect on ≥1 measurable metric, over functions with ≥1
  measurable metric), so abstained byte_match isn't a failure and ARM/PE still
  count via GED/types.
- The LLM backends run as a separate, sample-set-gated invocation — see
  [decompilers.md](decompilers.md).

## Overlays, finalize, and rebuilds — where the published numbers come from

**The published metric numbers are the reeval OVERLAYS, not the checkpoint
inline values — and `function_results.json` is only ever written through
`decbench/results_store.py`.**

`results/<tree>/{ged,type_match,byte_match}_new.json` (from
`scripts/reeval_{ged,typematch}.py` / `reeval_bytematch.py`) carry the
corrected values (sanitized decompiled parses, per-TU source matching,
non-finite dropped, compilability fixup); the per-project checkpoints still
hold the ORIGINAL inline values from each decompiler's first evaluation.

The canonical rebuild is `scripts/finalize_results.py <tree>` (also what
`run_benchmark.py`'s finalize calls): ALL checkpoints (never scoped — a
`-- project` resume finalizes the whole tree and writes a full
`scoreboard.toml`, so the old "additive resume leaves a SCOPED scoreboard"
gotcha is fixed), overlays applied SLICE-scoped (a (opt×proj×bin×dec) slice
with no overlay entries keeps its inline values; `ged_new.slices.json` marks
evaluated-but-empty GED slices so they clear instead — the 2026-07-22
kuna@betaflight wipe class), sample-set pinned to `sample_set_manifest.json`,
and a COVERAGE GUARD that refuses any unexplained shrink of published
coverage (`--allow-drops` / `DECBENCH_ALLOW_DROPS=1` overrides;
`--exclude-project`/`--exclude-decompiler` whitelist intended removals).
`--audit` scans checkpoints/artifacts/overlays/published for silent gaps.
After adding a decompiler, refresh the overlays and re-finalize before
publishing.

```bash
# Recompute ONLY byte_match over an existing tree WITHOUT re-decompiling
# (uses stored decompiled/*.c + compiled binaries); parallel, resumable.
# Used to refresh after a byte_match metric change:
python scripts/reeval_bytematch.py results/sailr_full 40   # -> byte_match_new.json
python scripts/rebuild_function_data.py results/sailr_full # -> function_results.json +
#   scoreboard.toml (merges the new byte_match, rebuilds view samples + compile
#   rates + sample sources, recomputes the scoreboard)

# CANONICAL rebuild of the derived files from ALL checkpoints + overlays
# (guarded). --audit scans for silent coverage gaps:
python scripts/finalize_results.py results/full_run [--audit|--render]
#   [--exclude-project N] [--exclude-decompiler N] [--allow-drops]

# Info writers — re-run after ANY function_results rebuild (the rebuild does
# NOT repopulate them):
python scripts/compute_dataset_info.py results/sailr_full  # FunctionData.dataset_info (sole
#   writer: About-page corpus LOC + Joern parse-health stats)
python scripts/compute_cost_info.py results/full_run llm_traces  # FunctionData.cost_info (sole
#   writer: the data page's cost section FACTS — batch decompile times from decompiled/*.toml
#   headers + LLM per-fn times/tokens via scoring/cost.py, structured fields preferred over the
#   trace scan). Prices are NOT stored: content/pricing.toml is applied at render
#   time, so a price fix needs only a re-render.

# Re-render: decbench report results/sailr_full/scoreboard.toml
```

Notes:

- The on-disk results tree may be a PARTIAL snapshot (some projects have no
  decompiled .c); rebuild DROPS byte_match for functions whose artifact is
  gone so the column is uniformly the new metric (per-metric denominators
  already differ).
- Sample source extraction needs `.c`/`.i` next to the binary. Compile now
  `rglob`s `.c` sources; older trees' samples used the preprocessed `.i`
  fallback (`SampleEntry.source_status` `"preprocessed"`). A rebuild via
  `scripts/rebuild_function_data.py` re-extracts sample sources.

## Finding improvement targets

Functions where a BASE decompiler beats a TARGET on a metric (respects each
metric's direction; `--perfect-only` = base is a perfect match, e.g. GED 0).
Reads a results tree's `function_results.json` and resolves each case to its
binary path + function symbol/address on disk:

```bash
decbench improvements results/full_run -b angr -t kuna -m ged --perfect-only
```
