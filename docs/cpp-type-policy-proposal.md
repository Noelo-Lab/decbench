# C++ type policy v1 — proposal for upstream review

Status: **experimental proposal, not an official DecBench policy**. This is a
separate, explicitly configured `CppTypeMatchMetric`. It is not registered among
default metrics and does not enter `type_match`, the public Union, or rankings.
Existing C scoring remains under its existing policy. Adoption requires upstream
review, a qualified population, and a new policy-versioned full rescore.

## Why separate views

A source `int&` and an ABI pointer are different answers to different questions.
MSVC `long` and GCC LP64 `long` have different widths. C++ `long` and `int` have
different language identities even where both have 32-bit storage. Removing
namespace qualification or treating any object with the same size as the same
type would lose more information than a C++ metric should permit.

The ground truth retains source information independently from scoring. We
propose publishing **source** and **ABI** results side by side; neither is silently
substituted for the other. Which view, if either, enters Union is an upstream
policy decision. This implementation does not make that decision.

## Implemented v1 comparison contract

| Feature | Source view | ABI storage view |
| --- | --- | --- |
| Integer | signedness, width, fundamental rank | signedness and width |
| Float | category and width | category and width |
| `bool`, plain/UTF character types | distinct categories | distinct categories retained |
| `const`, `volatile` | compared at each indirection level | erased as no storage change |
| Ordinary pointer | level and pointee type | level and pointee representation |
| `T&`, `T&&` | distinct from each other and from `T*` | explicit pointer projection |
| Fixed arrays | all dimensions and element type | all dimensions retained; no decay |
| Oracle typedef | resolved by the debug type graph | resolved / projected |
| Recovered fixed-width/platform alias | no inferred fundamental rank credit | documented storage aliases supported |
| Unknown `undefinedN` | incorrect | incorrect; width alone earns no credit |
| Namespace/class/template/enum | unsupported in v1 | unsupported in v1 |
| Object fields, inheritance, vtables | unsupported in v1 | unsupported in v1 |
| Function/member pointers | unsupported in v1 | unsupported in v1 |

Plain `char` deliberately remains distinct from `signed char`/`unsigned char` in
both views; this first profile does not infer compiler-default character
signedness. Long double, wchar_t, nonstandard scalars and vector types abstain.
An explicit `LP64`, `LLP64`, or `ILP32` data model is mandatory. Oracle scalar and
pointer widths must agree with it. A recovered supplied size inconsistent with
its own type is incorrect. C++ RTTI and exception behavior are not type accuracy.

The DWARF reader follows actual type references instead of the legacy flattened
type-name sets, retaining reference category, nested cv and array dimensions.
PDB source and ABI spelling remain separate. PDB modifiers on a pointer now
describe the pointer (`int* const`), not its pointee (`const int*`).

## Identity, correspondence, and eligibility

1. Select an oracle function by exact image entry address. Ambiguous/ICF identities
   abstain; no name-only overload borrowing.
2. Exclude optimized-out variables uniformly. An unsupported oracle type,
   partial/computed storage, inline identity, incomplete formal classification,
   or unavailable correspondence makes the **whole function** unmeasurable.
   Never grade only its easy variables and call it perfect.
3. Reuse type-blind ABI argument, calibrated stack, and native address matching.
   PDB exposes no proven argument ordinals or backend stack origins; it therefore
   uses native addresses only. DWARF aggregate returns are excluded before using
   ABI formal positions. Thresholds stay at overlap 0.1 / ambiguity margin 0.03.
4. Validate every producer PC against the exact function's decoded instruction
   starts. Validation proves instruction membership, not that the producer's
   variable association is semantically correct. The producer owns that claim.
   A generated/demangled name may differ from the oracle spelling; the shared
   resolver admits a unique exact entry identity, and rejects ambiguous entries.
5. Missing code/evidence or unsupported recovered types are **incorrect**, not
   oracle exclusions. Producer names/types never choose variable matches.
6. Score correct oracle variables / all eligible oracle variables. Perfect means
   every one is correct. Extra recovery variables are reported, not used to pad
   the denominator. Report eligible count, exclusions by reason, correspondence
   coverage, and type decisions alongside perfect rates.

The two producer runs must share exactly the same oracle-eligible function set.
These supported-subset results must not be extrapolated to all C++ or combined
with the legacy C headline. Unmeasurable is not zero; missing recovery on an
otherwise eligible function is zero.

## API

```python
from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_type_match import CppTypeMatchMetric

metric = CppTypeMatchMetric(MetricConfig(
    use_cache=False,
    extra_options={"view": "source", "data_model": "LLP64"},
))
score = metric.compute_for_binary(result)
# Repeat with view="abi"; preserve separate result labels and populations.
```

Optional `preprocessed_sources=[Path(...)]` supplies evaluator-only TU/source
line correspondence. It must never be passed to the producer. No new runtime
dependencies are introduced by this profile. It currently does not use disk
score caches; its version is `cpp-types-v1-proposal`.

For a fixed comparison, pass the same `requested_functions=[(name, address), ...]`
to both producers' `compute_for_binary` calls. Missing entries become empty
recoveries before oracle eligibility is decided. An in-memory `CppOracleContext`
can share debug indexing and native instruction validation across views/tools;
it is not a persisted score cache. Keep the image and companion debug artifacts
immutable for that evaluation run.

## Fission producer integration

The raw `fission` backend replaces the previously non-runnable external entry.
Set `FISSION_BIN`, optionally `FISSION_RESOURCE_ROOT` and
`FISSION_WORKING_DIR`. It runs NIR, uses one load per requested image, sends only
entry addresses to `--addresses-file`, enforces timeouts, and forwards native
variable `addresses` unchanged into `VariableInfo`.

Fission already produces a conservative scalar-SSA high-variable definition/use
map. This change connects it to DecBench. It does **not** manufacture output-line
maps by spraying all variable PCs onto every line containing its name. NIR/HIR
statement occurrence provenance and parameter/stack provenance require further
producer work. Each backend needs one adapter for its native address convention;
evaluation's instruction validation and variable matching remain shared.

The legacy metric now recognizes direct variable PCs as well as line PCs when
choosing the native path (cache generation 22). Functions with neither retain
their prior fallback behavior. Address validation remains mandatory at producer
and final evaluator boundaries. PDB default scoring still abstains;
`pdb_abi_diagnostic=True` remains a separate legacy diagnostic.

## Remaining decisions before an official C++ benchmark

* Define semantic identity versus ABI layout for qualified nominal types,
  template arguments, anonymous/local types and ODR duplicates.
* Add oracle and recovered structural graphs for fields, offsets, sizes,
  bitfields, bases/virtual bases, padding and member pointers. Neither name nor
  total size alone is proof of object recovery. Decide separately whether names
  are required or structurally equivalent anonymous objects receive credit.
* Define split variables, inline instances, piecewise locations, hidden ABI
  parameters, unknown calling conventions and aggregate returns.
* Qualify source provenance/toolchains, PDB and dSYM support, then fix a balanced
  cross-platform population and publish exclusions independently of producers.
* Validate source/ABI profiles on real corpus outputs, compare unchanged C rows,
  run formal repository tests/CI, and obtain maintainer agreement before any
  headline migration. A scalar-only subset is not a complete C++ ranking.

References: [DecBench methodology](https://decbench.com/about/),
[LLVM CodeView type records](https://llvm.org/docs/PDB/CodeViewTypes.html).
