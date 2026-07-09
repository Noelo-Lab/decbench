# GED Metric Failure Catalog — decbench `results/full_run`

> **STATUS (branch `fix/metric-fairness-and-denominators`).** The dominant issues
> below are **FIXED** in this branch and applied on the next re-eval:
> - **Source-CFG merge / name-collision** (cat 1b + cat 2, the biggest win): source
>   CFGs are now cached **per translation unit** and matched TU-aware (own TU first,
>   then the non-degenerate/largest across TUs) — see
>   `decbench/utils/cfg.py::resolved_source_for_binary` + `best_source_by_name`,
>   `pipeline/evaluate.py`, `scripts/reeval_ged.py`.
> - **Empty-prototype vs genuine 1-block** (cat 1, the 1,963 branchless funcs): only
>   all-Nop single-block sources are excluded; genuine straight-line bodies are now
>   scored (`is_degenerate_source_cfg`). Non-finite GED is dropped from the
>   denominator at the recording layer (`metrics/base.py`) instead of counting as a
>   failure.
> - **binja `Loading...`** (cat 4): `update_analysis_and_wait()` + placeholder guard
>   in `decompilers/raw/binja_raw.py`.
>
> **STILL OPEN for a follow-up agent** (smaller, ~2.4k evals): cat 4 decompiled-parse
> breakers — array/aggregate return types `T [N] name(...)` (angr/phoenix/ghidra),
> binja `arg @ rax` register annotations, ida `__int128`, and binja's whole-file
> error-recovery cascade (parse each decompiled function individually instead of the
> concatenated file). These need a pre-parse cleanup pass in
> `decbench/utils/cfg.py::extract_cfgs_from_source`/`_from_decompilation`.

Scope: the 25 x86 **sailr** projects (the only ones with source CFGs / `ged_new.json`;
cps + malware have no source CFGs). 6 decompilers: angr, phoenix, ghidra, ida, binja,
kuna. 3 opt levels: O0, O2, O2-noinline. All numbers verified against the on-disk data
with `DECBENCH_NO_CACHE=1`. Machine-readable detail + capped examples in `catalog.json`;
per-category raw JSON in `cat*.json`.

## Headline

`ged_new.json` has **225,753** GED evals. Only **105,236 (46.6%)** are a real structural
comparison. **120,517 (53.4%)** return `value=inf` — the metric never compared anything
because the cached **source** CFG had <=1 node.

The dominant cause is NOT "Joern couldn't see the source." It is a **broken source-CFG
merge**: source CFGs are cached per project by function **name** with last-writer-wins
(`acc[proj].update(cfgs)` in `scripts/reeval_ged.py::build_source_cfgs`, mirrored in
`decbench/pipeline/evaluate.py` `all_source_cfgs.update(...)`), and the writes arrive in
**nondeterministic** `imap_unordered` order. Every `.i` that merely *declares* (prototypes)
a function yields a degenerate 1-node stub for it; whichever `.i` finishes last wins. So a
real body is routinely clobbered by a prototype stub from an unrelated translation unit.

PROVEN: parsed fresh, zlib **`deflate` = 176 nodes** and e2fsprogs **`e2fsck_pass1` = 443
nodes**; the cache stores both at **1 node**. In `compress.i` (which only calls `deflate`)
Joern emits `deflate` as a 1-node stub — that stub is what landed in the cache.

**~64-77% of the 120,517 inf evals are recoverable by fixing the merge alone** (77,236
strict / 92,774 loose — see cat1b), raising real-GED coverage by **~73-88%, nearly doubling
it**. Single highest-value fix; it also subsumes the name-collision problem (cat2).

---

## Category 1 — Degenerate / empty-prototype source CFG (<=1 node) -> `inf`

`ged.py` returns `inf` when `source_cfg.number_of_nodes() <= GED_MIN_SOURCE_NODES` (=1).

- Distinct source functions across the 25 pkls: **17,745**.
- Degenerate (<=1 node): **11,023 (62.1%)** — matches the ~62% claim exactly.
  - **Empty-prototype (declaration-only, body only Nop/markers): 9,060 (82.2%)** — matches ~82%.
  - **Genuine straight-line body (1 real block, no branches): 1,963 (17.8%)** — e.g.
    `keephome(){ return scan_infos(...); }`. Real functions dropped only because a branchless
    function is a single basic block.
- Inf **evals**: 120,517 (empty-proto 96,494 / straight-line 24,023);
  by opt O0 43,643 / O2 34,409 / O2-noinline 42,465; roughly even across decompilers (42-55%).
- Worst projects by inf evals: openssh-portable 57,111, coreutils 12,542, bash 8,181,
  zlib 6,136, gnutls 5,186, libedit 4,707.

Top empty-prototype names are classic **gnulib** helpers declared in kept project headers but
whose body lives in another (proto-clobbered or uncaptured) TU: `xmalloc` (8 projects),
`xrealloc`, `error_at_line`, `xstrdup`, `xalloc_die`, `last_component`, `error`, `gettime`,
`rpl_fcntl`, `base_len`, `xcalloc`, `mdir_name`, `strip_trailing_slashes`, `xmemdup`, ...

### Category 1b — how much of cat1 is actually RECOVERABLE (the real story)

For a degenerate cached function, if some decompiler produced a large branchy body, a real
source body demonstrably exists and was lost to the merge:

- **2,579** (proj,func) are cached <=1 node but ghidra decompiles >=2 branches (strict);
  **3,394** with >=1 branch or >=10 lines (loose). Worst offenders are core functions:
  `e2fsck_pass1` (394 ghidra branches), iproute2 `iplink_parse` (337), `BZ2_compressBlock`
  (259), zlib `deflate` (166), bash `execute_command_internal` (129), `brace_expand` (129),
  diffutils `diff_2_files` (169) — all currently `inf` for *every* decompiler.
- Mapped to evals: **77,236 inf evals (64%) recoverable (strict)** / **92,774 (77%) (loose)**.
  Recoverable inf by dec (strict): ghidra 18,528, ida 18,297, kuna 14,449, phoenix 11,791,
  angr 11,364, binja 2,807.
- Recoverable by project: bash 673, openssh 654, libselinux 184, libedit 174, tar 156, ...

Non-recoverable remainder (~23-36% of inf) = genuinely branchless straight-line functions
(correctly ~1 node) + helpers whose body was never captured in any `.i`.

---

## Category 2 — Name-collision / wrong-source CFG

Same merge bug, different symptom: a name **defined with different bodies in >1 binary**
(main, usage, per-program statics) is scored against ONE arbitrary cached version.

- **508 true-collision (opt,proj,func) groups** (structurally-different source across binaries,
  via ghidra control-flow-skeleton hashing) vs **5,615 harmless gnulib dups** (identical
  skeleton across binaries — same source compiled into each binary).
- **Wrong-source evals: 11,665 upper bound (8,457 finite/real-GED).** At most one binary per
  group can be the "correct" match; all others are scored against a wrong CFG.
- Worst names (bins / distinct ghidra skeletons / cached nodes):
  - coreutils `main` 108 / 97 / 34 -> ~635 wrong evals/opt; `usage` 107 / 54 / **4**.
  - shadow `main` 40 / 38 / 56 -> 234/opt (the proven `nologin` case: its own main = 5 nodes);
    `usage` 35 / 15 / **1** (cached winner is a prototype -> also `inf`), `process_flags` 22/18/163.
  - openssh `main` 12 / 12 / 275; sysvinit `main` 14 / 14 / 39; gnutls `main` 9 / 9 / 91.
- Per project wrong-source evals: coreutils 4,481, openssh 2,493, shadow 2,461, gnutls 836,
  sysvinit 449, dpkg 204, diffutils 157, libacl 148, zlib 138, bash 126.

cat1 n cat2 overlap: several collided names (shadow `usage`, openssh `sshfatal`,
`cleanup_exit`, `tilde_expand_filename`) have `cached_nodes=1` — the merge picked a prototype,
so every binary's copy is *both* collided and excluded as degenerate.

---

## Category 3 — Binary Ninja `Loading...` placeholder (a decompile bug, tagged distinctly)

`binja_raw.py` dumps HLIL before per-function analysis is ready, emitting a literal
`Loading...` body (signature present, no code). Not a Joern failure, but it produces zero GED
coverage for those functions.

- O0: **18,018 / 24,757 = 72.8% Loading** (matches ~73%). All opts: **49,989 / 66,495 = 75.2%**
  (includes cps/malware binja files). Why binja has only ~10.6k GED evals vs ~50k for ghidra/ida.
- **28 binaries are 100% Loading**, incl. bash (1,053 fns), openssh `ssh`/`ssh-add`/`ssh-agent`,
  iproute2 `ip` (757), e2fsprogs `e2fsck` (409), coreutils `ls` (216), dpkg `dpkg` (238),
  cleanflight. Larger binaries lose the analysis race; small ones (base-passwd, gzip, shadow,
  zlib, cronie) are 0% Loading.

---

## Category 4 — Decompiled-parse failures (decompiler produced a real body, Joern got no CFG)

Counts across all opts: angr **525**, phoenix **541**, ida **452**, binja **826**,
ghidra **40**, **kuna 0**. Breakers (all confirmed by parsing minimal repros):

- **angr / phoenix / ghidra — aggregate/array return type.** Functions returning a
  struct/aggregate by value are rendered `T [N] name(...)` (`unsigned int [4] read_tree(void)`,
  angr's bogus `unsigned int [1277633] pqdownheap`; ghidra's `undefined1 [16] wrap_db_fetch`).
  Joern parses **nothing** for such a function. ~all of angr (524/525), phoenix (540/541),
  ghidra (36/40).
- **binja — `arg @ rax` register annotations** in the signature
  (`rpl_fcntl(..., char arg3 @ rax)`) -> Joern parses nothing (182). `int128_t` alone is fine.
- **binja — whole-file parse cascade (~538).** Functions that parse fine *in isolation*
  (diffutils `print_context_script`, `find_function`) are dropped when the whole
  `binja_<bin>.c` is parsed at once (dense with `@reg`-malformed neighbors + Loading stubs).
  Confirmed: `binja_diff.c` produced 18 non-Loading fns, Joern kept 14.
- **ida — `__int128` params/returns** (`unsigned __int128 a1`) -> Joern parses nothing; plus
  multi-underscore marker<->symbol name mismatches (`__fdnlist` vs parsed `_fdnlist`).
- **kuna — 0.** kuna output is Joern-clean.

---

## Category 5 — Source-parse outright failures

**Effectively nonexistent.** Header-stripping (`strip_system_headers`) eliminated the old
Joern timeouts. Probe of the 2 largest `.i` per project (49 files): **0 exceptions, 0 empty
returns**. The many degenerate CFGs *within* a parsed file are prototype stubs (cat1), not
parse failures.

---

## Prioritized fix list (by GED-coverage payoff)

1. **Fix the source-CFG merge — by far the biggest win.** Root cause of cat1b AND cat2.
   - Best: **key source CFGs per translation unit** and match each binary's decompiled function
     to the definition from that binary's OWN `.i` (per-program `main`/`usage` from the
     program's own TU; shared-lib functions are identical everywhere). Fixes both
     prototype-clobber and cross-program collisions.
   - Minimal interim: when merging same-named CFGs, **keep the one with the most nodes** (a real
     definition always beats a prototype stub). Instantly recovers the ~77k-93k recoverable inf
     evals (cat1b); does not fully fix cat2 collisions between two real definitions.
   - Payoff: real-GED coverage ~105k -> ~180-200k evals (~ +73-88%), plus 8.5k finite evals
     stop being scored against the wrong function.

2. **Fix cat4 decompiled-parse breakers (cheap, ~2.4k evals, mostly uniform per dec).** In a
   pre-parse cleanup / `extract_cfgs_from_decompilation`: rewrite `T [N] name(...)` return types
   to `T name(...)` (fixes angr/phoenix/ghidra ~1.1k); strip binja `@ <reg>` annotations (~182);
   rewrite `__int128` (ida chunk); and **parse each decompiled function individually** rather
   than the whole binary file to stop the binja error-recovery cascade (~538).

3. **Fix binja `Loading...` (cat3) in `binja_raw.py`.** Biggest single-decompiler hole — ~75%
   of binja bodies and 28 whole binaries produce no GED at all. Ensure per-function analysis is
   complete before rendering HLIL (await analysis / retry on `Loading...`).

4. **Decide policy for branchless straight-line source (1,963 real functions, cat1).** Excluded
   as `inf` only because a branchless function is one basic block. Consider scoring them
   (node/edge match) instead of dropping — lower priority, independent of the merge fix.
