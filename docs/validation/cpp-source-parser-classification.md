# C++ source-parser classification and bounded native MSVC control

This follow-up changes diagnostic exclusion labels, not eligibility, metric
arithmetic or defaults. The C++ profiles remain experimental and outside Union.

## Six new-image Windows mismatches

The recollected WinSparkle images have different native identities from the
frozen 250-function pilot. Their preprocessing cannot be attached to old images.
The separate recollection is frozen at Hugging Face revision
`ebe719316aa303e860f75a362bc3ab740b31ff2d`, under `recollection-v1/`:

https://huggingface.co/datasets/sjkim1127/decbench-cpp-qualification/tree/ebe719316aa303e860f75a362bc3ab740b31ff2d/recollection-v1

All six apparent `source_name_mismatch` rows resolve inside an erroneous
Tree-sitter definition named `DefDlgProcW`. Recovery starts at a Windows SDK
prototype, treats a subsequent enum as its body, and swallows roughly 200,000
physical lines including unrelated STL methods. Four affected rows are O0, one
O2 and one O2-noinline. This is evidence of source-front-end failure; the
recovered name cannot establish a native/source identity conflict.

`SourceCfgIndex.resolve()` now checks an error-bearing definition before its
name/template classification. It still rejects the span and never invokes CFG
parsing for it. It does not traverse swallowed definitions, relax name guards,
filter Windows SDK paths, rewrite sources or qualify template instantiations.
Four synthetic regressions cover matching and different recovered/native names,
with and without a template prefix.
Real-image replay changes exactly six labels to `source_syntax_error`; all
previously connected source definitions remain connected. The underlying SDK TU
parse failure remains unresolved. A compiler-confirmed minimized reproduction
has not yet been obtained; an isolated SDK prototype alone parses successfully.

## Fixed 250-function regression replay

A fresh cache-disabled replay uses all 45 cells and the same saved producer
outputs as the baseline at `81efc86dc9a0af22cb8d90e766b3e5a5e77f869c`.
All four tools retain source eligibility 56/250 and type eligibility 26/250.
All individual GED/type results are unchanged. Seven already excluded functions
change labels (three name mismatches and four template exclusions become source
syntax errors); each appears in all four reports. No function is added or lost.
This is separate from the six new-image Windows cases above.

## Native MSVC controlled family

A separate, handwritten compiler control exercises `Pair` field reads, lvalue
reference updates and conditional reference selection. This is a pipeline probe,
not a corpus-quality result or an addition to the scored population. It excludes
implicit object lifetime, templates and exception behavior.

The reproducible collector and saved producer plan are in the author's corpus
repository, commit `52f8f5277a614a6be770af6271c0fb2ba21e5e7f`:

https://github.com/sjkim1127/Decbench_SampleSet/tree/52f8f5277a614a6be770af6271c0fb2ba21e5e7f/targets/qualification-controls

Original native MSVC artifacts, run `39818175807`:

https://github.com/sjkim1127/Decbench_SampleSet/actions/runs/39818175807

Recompilation and independent original rebuild, run `39818822625`:

https://github.com/sjkim1127/Decbench_SampleSet/actions/runs/39818822625

Both runs succeed. MSVC version is `19.51.36260.0`, x64, with `/Od /Ob0`,
`/O2`, and `/O2 /Ob0` respectively. Native PE/PDB GUID, Age, sections and exact
procedure extents are checked by the existing readers. Removing the producer
input's debug directory and CodeView payload preserves executable-section bytes.
Producers receive isolated images and three entry PCs per image, never oracle
source/PDB data. No original or recovered program is executed.

All four producers emit 9/9 nonempty functions and connect 9/9 source and output
CFGs. Source CFG topology is definition-only; it does not establish semantic
correctness. The O0 PDB lacks explicit formal classification, so its three
functions remain type exclusions. Both O2 modes admit 6/6 functions per tool in
both type views; source-view perfect is 0/6 for every tool, ABI-view perfect is
0/6 Fission, 2/6 Kuna, 0/6 angr, 2/6 Ghidra.

| Producer version | Requested | Compiles and links | Exact native code |
| --- | ---: | ---: | ---: |
| Frozen Fission CLI 0.2.3 | 9 | 8 | 4 |
| Kuna 1.808 | 9 | 9 | 5 |
| angr 9.2.213 | 9 | 9 | 5 |
| Ghidra 12.0.4 | 9 | 9 | 5 |

Each output is compiled separately by the same MSVC version/toolset with the
original code-generation flags. All receive the same five fixed pseudo-type
aliases and an `extern "C"` linkage wrapper; output expressions, declarations
and types are otherwise unchanged. No compiler-driven repair or oracle source
injection occurs. Fission O0 has one rejected `uint8_t*` to `int*` assignment.
Successful compilation does not establish defined behavior: angr O0's field-read
output contains uninitialized pointers, and its reference selector declares
`unsigned long`, which is only 32 bits under LLP64.

Exact bytes are extracted only from matched native PDB procedure ranges.
Capstone must decode every byte before comparison. Existing branch/PC-relative
normalization and nop skipping give the same equality counts in this probe;
these diagnostic counts are not official `byte_match` scores. Original rebuilds
preserve all nine procedure byte sequences. Two producer runs preserve all 36
function records after excluding only `computation_time`.

Runtime parity, arbitrary MSVC C++ output repair, corpus-wide MSVC byte scoring,
full-TU parsing and general Windows qualification remain unproven. No default
metric/cache generation, Rust-Joern pin, result overlay, site or dataset flags
are changed. Full local evidence is retained under
`Fission/benchmark/artifacts/cpp-msvc-source-slice/2026-10-22/`.
