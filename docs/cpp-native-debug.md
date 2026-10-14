# C++ corpus: native debug transport

## Scope of this change

The qualification pilot contains 18 ELF/DWARF, 18 native MSVC PE/PDB and 9
Mach-O/dSYM images. The first implementation step adds thin Mach-O detection,
file-backed executable regions, linked address bases and UUID-matched dSYM
transport to the existing `binfmt` owner. Existing DWARF function identities,
source declaration hints and `NativeCodeResolver` consume that same reader.

This change depends on PR #91's collision-safe C++ function identity work and
includes upstream main through `14e14b87429043aa06f64e067847ac0a925e41a6`.
It adds no production dependency: LIEF, pyelftools and Capstone already exist.

## Reader contract

`binfmt.dwarf_info(image)` reads embedded DWARF or the canonical companion:

```text
image.dSYM/Contents/Resources/DWARF/image
```

An evaluator can also pass `debug_path=` pointing to that bundle or its DWARF
file. A companion must be a thin Mach-O with the image's architecture, address
width and LC_UUID. Mismatching or missing companions return no DWARF. Universal
images are not selected implicitly. `__debug_str_offs` is translated to DWARF's
full `.debug_str_offsets` name.

The reader does not search unrelated directories or copy debug files to
producer inputs. The isolated qualification inputs have no adjacent dSYM.
Mach-O address bases exclude `__PAGEZERO` and use file-backed load segments;
both dylib base zero and executable base `0x100000000` occur in the measured
corpus. Function bounds and instruction starts come from the native image,
not the dSYM's placeholder code sections.

TypeMatch cache generation moves from 19 to 20 because Mach-O ground truth that
previously appeared absent can now be read. The C++ type normalization and
correspondence policy are unchanged.

## Measured corpus evidence

Data snapshot: `sjkim1127/decbench-cpp-qualification` at
`07dd95dbe6214b8a78fc1e4a55961ab515986489`.

| Check | Before | After |
|---|---:|---:|
| macOS images recognized / readable dSYM | 0 / 9 | 9 / 9 |
| recorded macOS source-function ranges resolved | unavailable | 4,129 / 4,129 |
| ELF images with readable DWARF | 18 / 18 | 18 / 18 |
| MSVC images with readable DWARF | 0 / 18 | 0 / 18 |

All nine macOS images cover three programs and O0/O2/O2-noinline. Every recorded
source function was resolved to its native instruction entry and exact extent.
A different project's dSYM was rejected by UUID. All isolated macOS inputs
returned no evaluator DWARF. ELF/PE format detection and CU counts match the
45-image baseline. Snappy ELF address-keyed type ground truth and source
declaration fingerprints are identical before/after across all three modes.

These are real-corpus transport/provenance checks, not recovered-code execution
parity, a full test-suite run, C++ type-policy validation or a decompiler score.
The local JSON reports, logs and reproduction probes are under Fission's
`benchmark/artifacts/cpp-native-debug/2026-10-13/` in the operator workspace.
The portable [evidence summary](validation/cpp-native-debug-summary.json)
records the immutable data revision, validated code commit, per-image counts,
ELF comparison fingerprints and validation limits, without local binary paths.

## Review and submission

The feature is prepared separately from PR #91. While #91 remains open, a
`main`-based PR from this branch would include its prerequisite changes.
After #91 merges, replay this feature and its evidence-only follow-up onto
the then-current upstream main and inspect the resulting diff before opening
the separate PR. Do not merge the prerequisite into upstream main from this
branch or publish scores as part of the reader change.

Full repository regression tests and an end-to-end metric run remain pending.
The repository's Pages workflow deploys existing site files; it is not a
Python regression-test gate. Native debug transport checks should be reviewed
separately from those remaining validations.

## Remaining evaluation work

1. Native PDB function/storage/type ground truth, using CodeView GUID/Age and
   address-qualified identity. A PE parser is not a PDB type reader.
2. MSVC compiler/ABI provenance and a matching recompile lane; a MinGW compiler
   must not be treated as an MSVC recompiler merely because both emit PE.
3. Explicit unsupported/missing-oracle eligibility, rather than interpreting
   unavailable truth as a decompiler failure or perfect result.
4. A versioned C++ scoring contract separating source-level types, object
   layout, ABI representation and legacy C-oriented correspondence.
5. End-to-end source/decompiler CFG integration and corpus scoring with an
   agreed population. Native transport availability alone does not make any
   qualification record scoring-ready.
