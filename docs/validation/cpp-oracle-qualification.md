# C++ oracle coverage and recompiler target boundaries

Status: local follow-up to PR #103 at `ea2b461`. Not an official C++ policy,
leaderboard update or decompiler quality improvement. No Fission code changed.

## Frozen measurement

Qualification-v2 revision `07dd95dbe6214b8a78fc1e4a55961ab515986489`, sample SHA256
`f432c528e3071efa60fdaecc132aafa8c351e386bf7203d252e2875d6de02620`:
250 unchanged requests across 45 cells (Linux 108, Windows 97, macOS 45).
Frozen Fission and Kuna 1.808 outputs are re-ingested; no producer or corpus
program is executed. This is not a comparison against current/latest producers.

| Diagnostic | Baseline | Candidate |
| --- | ---: | ---: |
| Common source CFG eligible | 48 | 54 |
| Fission paired / distance zero | 48 / 18 | 54 / 18 |
| Kuna paired / distance zero | 47 / 20 | 53 / 21 |

All existing measured function results are identical, with no lost source row.
Two fresh source AST / source CFG / producer CFG passes per cell are identical
for 45/45 cells with metric caches disabled. Each cell shares an immutable native
index between its two passes. Native facts are hash-bound, not a metric cache.
Producer raw output is reused, not regenerated.

Two previously filtered third-party source definitions are now connected.
Retaining requested headers also prevents four project definitions from being
misparsed with incomplete surrounding source scopes. Five new identities match
qualified names and lines in independent original source bundles; the sixth
matches the raw parser's leaf name and line, with its namespace declarations
inspected directly. The remaining two macro-decorated source declarations have
the same raw-parser limitation as before. This bounded audit is not independent
build/link qualification or execution parity.

The 42 previous `missing_source_origin` entries are now: 2 connected, 38 rejected
as unqualified template specializations, 1 without a containing definition and
1 without exactly one real parser definition. Missing TU/source-line evidence is
not repaired by name/path guessing. No request is removed or resampled.

## Recompilation correctness

A native probe on this Darwin/arm64 host reproduced selection of `/usr/bin/gcc`
for ELF/AArch64, followed by emission of a Mach-O/AArch64 object. Matching CPU
architecture did not imply matching output format. No published score was
recomputed or inferred from this probe.

Bare `gcc` is now selected for native ELF architectures only on Linux; other
hosts require an explicit existing cross-ELF compiler. Compiled relocatable
objects must match the original format family, architecture and bitness before
byte extraction. Ordinary COFF objects belong to the PE target family.
Unknown/incompatible targets return explicit abstention and are excluded from
binary aggregates. Compatible objects retain the existing byte comparison.
Byte-match cache generation is 9; the new target identity is also in its key.

Read-only inspection of all 250 requested native entries reports no available
legacy recompiler on this Mac: 108 Linux requests need absent
`aarch64-linux-gnu-gcc`; 142 Windows/Mach-O requests have no legacy recompiler.
This is a toolchain capability audit, not a C++ byte-match run. Format/ISA checks
do not prove matching compiler family/version, C++ ABI, standard library,
exception/unwind configuration, or complete original command flags.

## Remaining gates

* **Artifacts:** 27 Windows source-TU misses (Detours 16, WinSparkle 11) have no
  retained `.ii` bundle; 19 other Windows requests have no usable native file/line
  fact. Recollect evidence from the same build or introduce a separately frozen
  corpus revision. Rebuilding a new binary is not proof for the old address plan.
* **Templates:** 84 requests now reach the specialization policy boundary.
  A concrete instantiated AST/CFG and proven native template arguments are needed
  before conditional compilation, `if constexpr` and overload resolution can be
  interpreted. Generic template bodies are not substituted as instance oracles.
* **Lifetime/exceptions:** explicit definition CFG remains diagnostic only.
  Implicit construction/destruction, cleanup on early exits, exceptions/unwinding
  and full-TU callee context are unqualified. Missing syntax does not prove that
  these effects are absent, and newly connected object-using functions earn no
  full semantic qualification.
* **Types:** split/computed DWARF locations, unknown legacy PDB formal status,
  incomplete objects and unknown vptr offsets still abstain. Native audit details
  are retained; storage positions are not used to guess formal classification.
  The prior 26/250 type-policy population has not been expanded or re-scored here.
* **C++ recompilation:** qualify GCC/MSVC/Clang commands, original compiler and
  target ABI evidence, then validate reconstructed C/C++ under the chosen policy.
  Passing scalar/COFF fixtures or the new object check is not full C++ support.

## Validation and evidence

* Focused workflow locally: 246 passed, 5 platform-specific skips; Black, Ruff and
  existing C++ owner mypy checks pass. New fixtures cover a real system-header
  definition and ELF/Mach-O/COFF target identification without guest execution.
* Full baseline: 907 passed / 19 failed / 28 skipped / 24 errors.
* Full candidate: 927 passed / 19 failed / 28 skipped / 24 errors.
  All 43 existing failure/error identities are unchanged; none added or removed.
* New remote CI has not run for this unsubmitted follow-up. Existing head CI is
  not evidence for this patch. No website/overlay/Union/Hugging Face change.

Complete local artifacts, inputs, per-cell pairs, source identity audit, native
location inventory, known failures and proposed patch are retained under Fission
`benchmark/artifacts/cpp-oracle-qualification/2026-10-18/`. Public submission
requires complete human review under `docs/agents.md`.
