# changelog

User-visible changes to the DecBench benchmark and site, newest first. Dates are
when the change reached the published site. Internal refactors and tooling are
listed only when they changed published numbers.

### 2026-07-22

- **Codex joins the leaderboard** on the `sample-set` dataset (~250 functions
  sampled across the corpus): an agentic LLM decompiler driven one function at a
  time, now shown with its logo and official name. LLM backends run only on
  `sample-set` for cost reasons — their rows are omitted on the other presets
  rather than shown as near-total failures.
- New **insights** and **changelog** (this page) pages.
- The **view** page can browse the `sample-set` functions directly (a
  `sample-set` option in the difficulty selector), and selecting the
  `sample-set` preset shows which projects were sampled.
- The **historical** page was removed; the per-decompiler **Compiles** rate
  moved from the leaderboard to its own table on the **distance** page.

### 2026-07-21

- **Recompilation (byte_match) metric fairness pass.** Fixed compilability
  fixup gaps, unlinked `[rip]` operand handling, and dropped `-f*` flags that
  penalized decompilers for toolchain differences rather than wrong code. A new
  per-decompiler **Compiles** rate was published alongside it.
- **dewolf** results completed across the full corpus (sharded Binary Ninja
  drivers; per-function hang cap).

### 2026-07-20

- The site moved to **decbench.com**.
- **Light mode**: a sidebar toggle switches between the terminal-dark default
  and a terminal-on-paper light theme.
- Leaderboard rows show each decompiler's **logo**, official name, and version.

### 2026-07-19

- **r2dec** results published (radare2's r2dec plugin, run via Docker on the
  real plugin — not the asm-like native fallback).
- Fixed a regression where a resume run silently reverted all three metric
  columns to stale pre-fairness values (Kuna briefly showed 22% instead of 47%).

### 2026-07-18

- **Linkable URLs**: every page has its own address (`/leaderboard/`,
  `/view/`, ...) and the selected dataset / normalize toggle / viewed function
  live in the URL, so any configuration can be shared.
- The **about** page's metric visualizations were rebuilt (CFG diff for GED,
  recompiled-assembly diff for byte_match, a stack-frame matching diagram for
  type_match) after a rendering bug left them blank.
- **Syntax highlighting** for all source and decompiled code on the site.
- The **view** page recovers source for firmware targets from preprocessed
  units (`.i`) when the original `.c` was not captured, and explains the reason
  whenever source cannot be shown.

### 2026-07-16 — v1.0

- The benchmark is versioned **v1.0** and the report became this site.
- **Union** replaced the old Overall column: the share of functions a
  decompiler recovers perfectly on *at least one* metric.
- Views consolidated: **about** absorbed metrics + dataset; **view** absorbed
  compare + hardest (with easy/medium/hard difficulty tiers).
- Dataset presets: `unoptimized` / `optimized` / `inlined` / `large` /
  `sample-set`.
- New backends: **dewolf** and **Kuna**; **phoenix** runs but is hidden from
  the site.

### 2026-07-12 .. 2026-07-15 — fairness overhauls

- Every decompiler "failure" was traced to benchmark bugs and fixed: phantom
  function rows, PE/Thumb address mismatches, timeout parity across backends,
  Joern parse failures on decompiler-specific C quirks. Error rates dropped
  across the board (e.g. IDA 17% → 4.5%, Ghidra 28% → 16%).
- GED: source CFGs are matched per translation unit (no more cross-file name
  collisions) and degenerate source CFGs are excluded rather than rewarded.
- type_match: per-function stack-offset calibration so frame-relative variables
  align with DWARF ground truth at every optimization level.

### 2026-06-25 .. 2026-06-30 — v2 and corpus expansion

- Declib-free native backends for angr, Ghidra, IDA, Binary Ninja; multi-version
  decompiler support (`ghidra@12.0` vs `ghidra@12.1`); content-addressed metric
  caching; reusable compiled-binary datasets.
- Corpus: 26 sailr-eval Debian packages joined by **11 cross-compiled ARM
  firmware targets** (flight controllers, RTOSes, bootloaders) and **6 real
  malware samples** (compiled in isolation, never executed; source never
  published).
- Windows/PE support in type_match and byte_match.

### 2026-02 .. 2026-04 — origins

- Started from sailr-eval; rebuilt around the three-metric system:
  **Structural Correctness (GED)**, **Type Correctness**, and **Recompilation
  Bytematch**, each scored against compiler ground truth (DWARF + the original
  toolchain) rather than taste.
