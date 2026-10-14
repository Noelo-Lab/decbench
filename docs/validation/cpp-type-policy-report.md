# C++ policy and Fission address transport — 2026-10-13

## Result

This is an upstream policy proposal / supported-subset prototype, not official
C++ qualification, decompiler quality improvement, or a public Union score.

| Measurement | Fission | Kuna 1.808 |
| --- | ---: | ---: |
| Functions with direct variable PCs | 142/250 | 222/250 |
| Variables with direct PCs | 955 | 1019 |
| Validated variable/address pairs | 9474 | 6910 |
| Invalid variable/address pairs | 0 | 0 |
| Proposed source-view perfect | 0/5 | 1/5 |
| Proposed ABI-view perfect | 0/5 | 1/5 |
| Legacy Windows ABI diagnostic measured | 19/97 | 32/97 |

Fission already had these 955 variable maps in frozen CLI output. The previous
evaluator ignored them when deciding whether a producer had native evidence,
requiring line maps instead. The adapter forwards them and the metric now uses
the native correspondence path. All 9,474 pairs are exact instruction starts
within their oracle function ranges. This validates membership, not the
semantic correctness of each variable's SSA association.

The fresh Windows transport run also exposed a producer/PDB spelling mismatch
at a correct entry. Native validation now admits one exact entry identity when
names differ, and rejects ambiguous entries. The final live Windows mapping
retained all three PCs; the Linux run retained 99 and macOS retained four.

Fission's legacy Windows diagnostic availability increased from 0 to 19, with
no new perfect function. This is transport availability, not improved recovery.
Thirteen of Kuna's 32 diagnostic functions still lack Fission native evidence;
other Windows exclusions are oracle/storage/identity limits. The diagnostic is
not an official C++ score and does not have the same producer denominator.

The new source and ABI profiles instead have identical oracle eligibility for
both tools on all 45 images. Only 5 of 250 functions qualify under v1;
the remaining 245 are explicitly excluded. Object types, inline identities,
unsupported locations and missing correspondence dominate the exclusions.
These few functions cannot support a C++ ranking or broad accuracy claim.

## Scope and reproducibility

Dataset revision `07dd95dbe6214b8a78fc1e4a55961ab515986489`, fixed 250-address sample
and original producer outputs are pinned in `summary.json`. Generation received
stripped inputs plus entry addresses only; no oracle types/source were supplied.
Both profiles were remeasured with disk caches disabled. Native oracle indexing
is shared within one immutable image and bounded to one image per process.

Three stripped functions from Linux Snappy O0, Windows Snappy O2 and macOS Ninja
O2 were generated twice through the final adapter. NIR code equalled the frozen
baseline; code and variable information were deterministic across repeats.
This is a transport check on three functions, not a fresh regeneration of 250
functions or recovered-program execution parity.

`measure_policy.py`, `run_cells.py`, `live_adapter.py` and per-image JSON files
provide the rerun path. This prototype passed scoped Black/Ruff and diff checks.
Formal pytest/CI and recovered-code execution were not run. The existing
type_match SIM105 warning is present on the prerequisite branch too.

## Next required work

Upstream must review the source/ABI contract and Union choice. The largest
coverage blocker is now structural object/field/base type ground truth and
recovered descriptors, followed by split/inline variable identity and reliable
formal/storage correspondence. Fission line occurrence and parameter/stack
provenance remain producer work; no line map was fabricated from variable names.
