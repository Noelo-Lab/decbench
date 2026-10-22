# C++ evaluation qualification gates (proposal)

This is an experimental qualification proposal for PR #103. It does not adopt
an official C++ metric, expand a scoring population, or change the default
GED/type/byte metrics or Union. Maintainers must approve a policy before adoption.

## Keep four evidence levels distinct

1. **Packaging:** immutable image, matching debug companion, preprocessed input
   and effective build commands. Preserve hashes, UUID/GUID/Age and original paths.
2. **Definition identity:** one native entry, one TU and one exact qualified definition.
   Every retained first-PC file/line candidate must resolve to that same definition. No basename or same-name fallback, including overloads.
3. **Syntactic CFG:** a parsed isolated definition with directed entry/exit roles.
   This is what `cpp-ged-origin-v3-diagnostic` currently reports. Its eligible
   population is not a population qualified for full C++ semantics.
4. **Semantic/effect qualification:** concrete instantiated definition, resolved
   object lifetimes and exceptional exits under the original build configuration.
   A syntactic match or compiler acceptance cannot supply this evidence alone.

### Reused native preparation

The C++ GED and type contexts now track canonical PDB/dSYM filesystem versions,
including an absent companion. Replacement, removal, appearance or modification
invalidates preparation; changes during reader preparation also fail evaluation.
The readers still perform UUID/GUID/Age validation. Filesystem versions are not a
cryptographic attestation against same-metadata tampering. No new debug search
path, copied debug input, or alternate companion is introduced.

Source indexes retain the exact decoded preprocessed input-text digest. Missing file/line evidence
now still reports native units, physical unit and compilation directory when
available, so recollection can target the original build. These fields do not
make an unproven source match eligible. When a PDB retains multiple file/line
rows at the same first PC, every candidate must uniquely resolve within the
proven TU to the same exact parsed definition. An unmapped candidate, different
definition or ambiguity abstains. The reader preserves the complete candidate
set separately from its legacy singular file/line hint; it does not select the
smallest line, use the symbol name to choose a candidate, or bypass template
qualification. See [the frozen replay](validation/cpp-first-pc-locations.md). Explicit debug-path overrides are not
accepted by these contexts; their snapshot covers the default native readers.

## Template policy

Generic template syntax is never substituted for a concrete binary instance.
A future instantiated-CFG profile must retain:

- exact native identity and range, specialization arguments and selected overload;
- complete original TU, macros, includes and compiler/target configuration;
- concrete semantic AST and instantiated body after `if constexpr`, substitution,
  overload resolution and dependent lookup;
- explicit handling of shared/ICF entries and compiler-generated variants.

Partial/explicit specialization and non-type arguments need the same proof.
No generic textual replacement of `T`, no choosing the largest body, and no
reselection of easier functions. Current unsupported instances remain excluded
from the diagnostic source population, with the original request retained.

## Lifetime and exceptional-path policy

The current diagnostic does not qualify implicit construction/destruction,
member/base initialization, temporaries, defaulted/deleted special members,
cleanup on early return, exception propagation, landing pads or unwinding.
Absence of `throw` in an isolated body does not prove that its calls cannot throw.

A future effect profile must use the same representation on source and producer
sides and retain normal/exceptional successors, ordered effect/call sites, object
construction/destruction and cleanup on every exit. Compiler ABI entry variants
and synthesized thunks require explicit identity. Do not compare a source graph
with implicit effects to an ordinary pseudocode CFG and call the difference a
decompiler error. Until both sides are qualified, report this dimension as
unmeasurable separately from the existing syntax-only diagnostic.

The existing source/ABI object type graph is a separate storage/type dimension;
complete field layout does not prove lifetime, RTTI or exception correctness.

## Recompilation contract

An eventual C++ byte comparison requires, independently of compilability:

- original compiler family/version and target triple, ABI and data model;
- exact per-TU compile/link flags, optimization/inlining, CPU features and macros;
- runtime/standard-library ABI, exception/unwind, RTTI, packing and visibility;
- exact source/header provenance and native function/entry variant correspondence;
- object format, architecture and bitness validation before byte extraction;
- an explicit policy for generated declarations/scaffolding, relocations and
  link-time changes (including LTO and ICF).

Missing/incompatible oracle or toolchain evidence abstains explicitly. For an
otherwise qualified population, producer compile failure remains a producer
failure rather than disappearing from the denominator. Clang targeting Windows
is not native MSVC; Clang targeting ELF is not the corpus's GCC 13.3. A matching
object triple alone is insufficient. The legacy byte metric remains unchanged.

### Reproducible bounded compiler control

```sh
PYTHONPATH=. python scripts/audit_cpp_toolchains.py \
  --compiler clang++ --source tests/fixtures/cpp_qualification.cpp \
  --output /absolute/path/to/artifacts/toolchain-fixture
```

The optional development script compiles a header-free explicit fixture for
ELF/AArch64, COFF/x86-64 MSVC ABI and Mach-O/arm64, at O0, O2 and O2-noinline.
It preserves compiler commands, source/preprocessing/AST/IR hashes and object
identities. It verifies data-model assertions, template instantiation, construction,
throw/exception IR and identical code sections after preprocessing roundtrip.
It neither links nor executes the fixture and produces no corpus score.
No compiler is added to the runtime dependency set.

The fixture proves only this bounded compiler path. It does not qualify original
MSVC/GCC versions, standard-library integration, recovered C++ compilation or
execution parity. Clang's [AST documentation](https://clang.llvm.org/docs/IntroductionToTheClangAST.html),
[cross-compilation guide](https://clang.llvm.org/docs/CrossCompilation.html) and
[toolchain components](https://clang.llvm.org/docs/Toolchain.html) describe the
compiler facilities used by this development probe.

## Rust-Joern candidate adoption gate

Replay identical prepared bytes with proven producer defects rejected first.
Retain every changed source/producer graph, directed topology and entry/exit
roles; graph counts alone cannot establish parity. Capture original Joern
references in isolated interpreters without the replacement shim. Differences
require an owner-level explanation and regression coverage before pin adoption.
Previously parsed invalid outputs stay rejected regardless of candidate syntax
support. Original-Joern agreement itself is not a C++ semantic certificate.

Keep the existing dependency pin until this review is complete. Candidate replay
results remain counterfactual diagnostics, separate from official scores.
