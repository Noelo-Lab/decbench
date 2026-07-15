# Kuna decompile-failure investigation (handoff)

**Status:** diagnosed, NOT fixed. This note is a handoff so another agent can fix
kuna's failures later. Written 2026-07-05 from a full-dataset audit of
`results/full_run` (40 projects, 806 binaries, 6 decompilers).

## TL;DR

Kuna has the **worst decompile-failure rate of any backend: 57.8%** (64,141 /
110,992 function-records marked `decompiled=false`). Almost none of that is kuna
being unable to *decompile* — genuine decompile errors (`unparsable`) are only
193 functions (0.3%). The failures are two separable **pipeline/backend** problems:

| cause | count | share of kuna failures | where |
| --- | ---: | ---: | --- |
| **not_identified** (kuna never produced a function at the address) | 53,576 | **84%** | almost all ARM (51,417) |
| **timeout** (binary hit kuna's wall-clock cap) | 10,049 | 16% | almost all x86 (9,719) |
| unparsable (kuna tried the function, decompile failed) | 193 | 0.3% | x86 |
| unknown (address unresolvable — PE import thunks) | 240 | 0.4% | PE |
| duplicate_relabel (Thumb-LSB/PE-base phantom rows) | 83 | 0.1% | — |

Per arch (from `scripts/analyze_failures.py --decompiler kuna`):
- **x86** (9,940 fails): 98% `timeout` (9,719), 184 `unparsable`, 34 `not_identified`.
- **ARM** (51,830 fails): 99% `not_identified` (51,417), 330 `timeout`.
- **PE** (2,371 fails): 2,125 `not_identified`, 240 `unknown`, 6 `unparsable`.

Reproduce anytime (reads the results tree + `checkpoints/*.pkl`, no re-decompile):
```
python scripts/analyze_failures.py results/full_run --decompiler kuna \
    --json /tmp/kuna_failreasons.json --examples 10
```
The category definitions (and the `duplicate_relabel` Thumb-LSB/PE-base bug that
affects all backends) are documented in the module docstring of
`scripts/analyze_failures.py`; the two items below are kuna-specific.

## Problem 1 (dominant): kuna identifies almost no functions on ARM

**51,417 ARM functions are `not_identified`** — kuna's analysis never produced a
function at the DWARF `low_pc`. For comparison, on the same stripped ARM firmware
Ghidra `not_identified` = 13,123 and IDA = 7,082, so this is **~4-7x worse than
its peers**, not an intrinsic "ARM is hard" effect. Kuna is a Ghidra/SLEIGH port,
so ARM/Thumb *should* be feasible.

Likely culprits to check (in order):
1. **Language/processor selection.** Does kuna pick the right SLEIGH language for
   a stripped ARM Cortex-M ELF (ARMv7-M / Thumb, little-endian)? If it defaults to
   ARM (not Thumb) or fails to load the language, function discovery collapses.
   Look at how `RawKunaDecompiler` (`decbench/decompilers/raw/kuna_raw.py`) invokes
   kuna and whether it passes an arch/language hint. The pipeline hands kuna a
   STRIPPED binary (no symbols / no ARM `$t`/`$a` mapping symbols), so kuna must
   infer Thumb itself — verify it does.
2. **Function discovery / analysis depth.** After loading, does kuna run the
   analyses that create functions (e.g. Ghidra's function-ID / decompiler-driven
   discovery)? On a stripped bare-metal image, functions reached only via the
   Cortex-M vector table + pointer tables need aggressive discovery. Check what
   `discover_functions` / the decompile pass in `kuna_raw.py` relies on.
3. **Sanity probe.** Run kuna directly on one ARM binary and count functions:
   e.g. `results/full_run/O0/chibios/compiled/ch` (stripped a copy first, as the
   pipeline does — see `_stripped_copy` in `scripts/run_benchmark.py`). Compare the
   function count to Ghidra/IDA on the same binary (IDA found 2553 on cleanflight;
   check kuna). If kuna finds ~0, it's a loading/language bug; if it finds many
   but at odd/shifted addresses, it's an address-translation issue.

Note: like the other backends, kuna only decompiles functions it auto-discovers
then `common.narrow_to_source`-filters by address — it never force-decompiles a
known target address. So "identify" here means kuna's own analysis, not our
filter. (A cross-cutting "force-decompile at target addresses" change would help
all backends but is out of scope here — see the taxonomy note.)

## Problem 2: kuna times out on large x86 binaries

**9,719 x86 functions are `timeout`.** Kuna's per-binary wall-clock is capped
hard at **120s** (`DECOMPILER_TIMEOUT["kuna"]`, `scripts/run_benchmark.py`; env
`DECBENCH_KUNA_TIMEOUT`), deliberately shorter than the global 300s because
**kuna hangs** and leaks JVM/tool processes at 100% CPU (there is a documented
incident: "kuna leaked 9 processes burning 100% CPU for 4+ hours"; see the
process-group-kill code in `_timed_decompile` and `RawKunaDecompiler`'s own kill
path). So big binaries (bash, coreutils multicall, openssh) don't finish and all
un-reached functions are counted as failures.

Fix options:
1. **Root-cause the hang** (preferred). If kuna no longer hangs, raise its timeout
   to the global 300s (or remove the special-case). The hang repro is referenced
   in the kuna repo's `tests/hang-repro/` (per the comment in run_benchmark.py).
2. **Interim:** raise `DECBENCH_KUNA_TIMEOUT` for large binaries only, or split
   multicall binaries. Keep the process-group SIGKILL on timeout regardless —
   removing it reintroduces the orphaned-process leak.

## Where things are

- Backend: `decbench/decompilers/raw/kuna_raw.py` (`RawKunaDecompiler`,
  registered as `kuna`; there is also a SLEIGH type-alias note in the top-level
  `CLAUDE.md`).
- Timeout + strip + driver: `scripts/run_benchmark.py`
  (`DECOMPILER_TIMEOUT`, `_stripped_copy`, `_timed_decompile`, `_relabel_to_dwarf`).
- Enumerate/narrow shared helpers: `decbench/decompilers/raw/common.py`
  (`narrow_to_source`, `should_skip_function`).
- Failure analyzer used for these numbers: `scripts/analyze_failures.py`.

## How to verify a fix

Re-decompile a couple of representative binaries with kuna (one big x86 e.g.
`bash`, one ARM e.g. `chibios`/`ch`) via `scripts/decompile_one.py`, rebuild the
per-function data, and re-run `scripts/analyze_failures.py --decompiler kuna` on
that subset. Success = `not_identified` on ARM drops toward Ghidra/IDA levels and
`timeout` on the big x86 binary drops to ~0.
