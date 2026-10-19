# C++ type policy v2 — proposal for upstream review

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

## Implemented v2 comparison contract

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
| Named complete objects | qualified identity and complete instance graph | complete instance layout graph; names erased |
| Enum | nominal identity, values, underlying type | underlying storage |
| Fields / ordinary bases | field names, offsets, types, access and base identity | offsets, field/base storage and relation |
| Virtual bases | explicit debug locator and base relation | locator and base storage; never offset zero |
| Vtables / RTTI | not a complete behavior/API metric | missing physical vptr evidence abstains |
| Function/member pointers | unsupported in v2 | unsupported in v2 |

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
   Never grade only its easy variables and call it perfect. Explicit
   `UnsupportedType` and native `PdbFormatError` are oracle abstentions only
   during oracle preparation. An unrelated parser/evaluator `ValueError` must
   surface as an evaluation failure; recovery scoring runs outside that boundary.
3. Reuse type-blind ABI argument, calibrated stack, and native address matching.
   PDB exposes no proven argument ordinals or backend stack origins; it therefore
   uses native addresses only. DWARF aggregate returns disable unproven
   formal ordinals; remaining correspondence must stand independently. Thresholds stay at overlap 0.1 / ambiguity margin 0.03.
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

Virtual-base locators still compare native debug encodings. This can be stricter
than binary-observable semantic equivalence across DWARF and CodeView; no
cross-format normalization is claimed. Maintainers must resolve this policy
question before official adoption.

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

A reproducible single-image entry point consumes canonical producer JSON and a
fixed requested population, without invoking a producer:

```bash
python scripts/evaluate_cpp_type_policy.py --binary original-with-debug \
  --decompilation producer-result.json --requested-functions functions.json \
  --view source --data-model LP64 --output cpp-source.json
# Repeat with --view abi and a distinct output file.
```

Optional `preprocessed_sources=[Path(...)]` supplies evaluator-only TU/source
line correspondence. It must never be passed to the producer. This branch adds
`tree-sitter-cpp>=0.23,<0.24` as a normal runtime dependency for C++ definition
extraction. The type profile itself adds no further runtime dependency. It does
not use disk score caches; its policy version is `cpp-types-v2-proposal`, and
its evaluator/cache revision is 3.

For a fixed comparison, pass the same `requested_functions=[(name, address), ...]`
to both producers' `compute_for_binary` calls. Missing entries become empty
recoveries before oracle eligibility is decided. An in-memory `CppOracleContext`
can share debug indexing and native instruction validation across views/tools;
it is not a persisted score cache. Keep the image and companion debug artifacts
immutable for that evaluation run.

## Fission producer integration

The raw `fission` backend replaces the previously non-runnable external entry.
Set `FISSION_BIN`, optionally `FISSION_RESOURCE_ROOT` and
`FISSION_WORKING_DIR`. Resolve the executable (including a relative
`FISSION_BIN` or PATH entry) to an absolute path before changing the child
working directory. It runs NIR, uses one load per requested image, sends only
entry addresses to `--addresses-file`, enforces timeouts, and forwards native
variable `addresses` unchanged into `VariableInfo`.

Fission's existing conservative scalar-SSA variable definition/use PCs remain
primary evidence. The companion Fission change also exports `line_mappings_nir`
and `line_mappings_hir`, each containing 1-based physical `line_number`, native
instruction `addresses`, and `defined_variables`. The adapter takes NIR maps
only. These are **partial assignment-result definition origins**, not all RHS
references or complete effect lineage. Header, predicate, ambiguous/cloned,
phi/input, repeated-definition and unproved lines remain unmapped. Old Fission
versions continue to transport direct variable PCs with no invented line maps.

`LineMapping.defined_variables=None` preserves the historical whole-line
contract. A supplied list scopes ownership: only those bindings can inherit
that line's PCs. Even on a scoped row a direct variable PC list takes precedence.
The adapter gives only those variables line occurrences; evaluation repeats the
same scope check. A scoped display name must be nonempty and unique among
all variables in the function. Shadowed/duplicate names inherit no scoped PCs;
direct per-variable addresses remain primary and legacy whole-line maps retain
their historical contract. A future stable binding-ID transport would be needed
to resolve those ambiguous names. Scoped rows outside the returned code are
rejected. Native instruction validation proves membership, not the producer's
semantic claim.

The legacy metric now recognizes direct variable PCs as well as line PCs when
choosing the native path (cache generation 24, including ambiguous-scope
rejection). Functions with neither retain their prior fallback behavior. Address validation remains mandatory at producer
and final evaluator boundaries. PDB default scoring still abstains;
`pdb_abi_diagnostic=True` remains a separate legacy diagnostic.

## Complete object graph contract

The native DWARF reader follows DIE edges for instance members, literal byte
positions or `data_bit_offset`, ordinary and virtual inheritance, enums, arrays,
modifiers and recursive ordinary pointers. A forward-only or anonymous object,
unsupported method/member pointer, legacy bit offset or uncertain location
abstains. CodeView follows actual TPI indices, LF_FIELDLIST continuations,
LF_MEMBER/BCLASS/VBCLASS/IVBCLASS, bitfield leaves and enum constants. A forward
record must resolve to exactly one complete identity; conflicting definitions
abstain. Methods/static members are not instance storage. CodeView VFUNCTAB
lacks its physical position: such a graph abstains rather than guessing zero.

Producer output can supply `metadata.type_graphs[complete_type_spelling]`:

```json
{
  "schema": "decbench-cpp-type-graph-v1",
  "root": "object",
  "nodes": {
    "object": {"kind": "record", "size": 4, "name": "demo::Object", "complete": true,
      "edges": [{"role": "field", "target": "integer", "name": "value",
                 "offset_bits": 0, "access": 3}]},
    "integer": {"kind": "signed", "size": 4, "rank": "int", "complete": true}
  }
}
```

Nodes use byte sizes; edges use bit offsets. All targets must exist. Partial
nodes, impossible extents, by-value cycles and missing virtual locators are
rejected. Pointer cycles are compared structurally; local node IDs and edge
ordering do not earn credit. Source comparison retains qualified names, cv,
rank, field names/access, enum values and inheritance. ABI comparison erases
names/cv/rank/access, projects references to pointers and enums to their
underlying storage. It retains base relations: it does not infer a flattened
base from a similarly named or sized recovered field. Virtual locators retain
their debug encoding; cross-format locator equivalence is not inferred.
Instance fields and bases are compared; this is not a complete class API metric.

Complete ordinary emitted C `struct`/`union` and typedef definitions are also
read with Tree-sitter. Natural layout is limited to explicit LP64/LLP64,
supported scalar/pointer/array fields, and unambiguous complete definitions.
Unknown class ABI, inheritance, packing, bitfields and alignment attributes
require explicit producer graphs. ILP32 record alignment is not guessed.
Opaque nominal spellings are incorrect recovery, never oracle exclusions.

## Validation and adoption

The `C++ evaluation contracts` workflow runs focused policy/provenance/source
identity regressions on Ubuntu, compiling actual DWARF and CodeView/PDB fixtures
with Clang and lld. Rust-Joern is the existing CFG dependency, pinned for this
lane. Style and type checks cover new policy owners. Full local repository
results and baseline failures are reported separately; skipped real-decompiler
or platform tests are not end-to-end success.

The fixed qualification measurements and exclusion inventory live in
`docs/validation/`. They describe a supported subset, not an official C++
ranking. Upstream must agree on source versus ABI headline policy, templates,
anonymous/ODR types, split/inline locations, hidden parameters, source
provenance, and a balanced qualified population before adoption and full rescore.
A contribution must follow DecBench's mandatory human review policy.

References: [DecBench methodology](https://decbench.com/about/),
[LLVM CodeView type records](https://llvm.org/docs/PDB/CodeViewTypes.html).

### Producer inspection

The supported-subset proposal now retains an optional producer language and
declaration contract plus bounded, oracle-free defect evidence. Invalid
recovered text receives zero after oracle eligibility; it never removes an
oracle-qualified function. See [producer inspection](cpp-producer-contract.md)
for scope, uncertainty and cache generation. CFG parsing remains separate from
source validity, and the diagnostic GED profile is version 2.
