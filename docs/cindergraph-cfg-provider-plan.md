# Replace Joern with Cindergraph in `mjbommar/decbench`

## Status and objective

**Implementation status: complete in the local fork branch
`plan/cindergraph-cfg-provider`; not pushed or submitted.** The implementation
now has a provider-neutral `decbench/cfg/` boundary, uses the pinned
Cindergraph package for both source and decompiled C, represents C++ as a typed
unsupported-language outcome, separates cache and artifact provenance, rejects
mixed-provider GED pairs, and removes the previous provider from the live
dependency and runtime paths. Historical site and snapshot artifacts were not
rewritten.

The fixed-population evidence and its limitations are recorded in
[`cfg-provider-validation.md`](cfg-provider-validation.md). Current validation:

- 202 focused CFG, pipeline, export, materialization, rendering, and metric
  tests pass, plus the provider contract tests for damaged text, preprocessing
  timeout evidence, core control-flow constructs, and cross-process
  determinism;
- the full suite passes 682 tests and skips 15 when its undeclared test-only
  `r2pipe` dependency is supplied; one host cgroup OOM-event test remains red
  independently of this change;
- Ruff, Black, and scoped mypy pass on every migration-owned Python path;
- the repository-wide mypy command still reports pre-existing errors outside
  the migration-owned paths;
- `uv build` succeeds, and installing the resulting wheel into a clean virtual
  environment installs Cindergraph 0.1.0 and no Joern package;
- `site/` and `snapshots/` have no diff.

This is a local implementation plan for a DecBench fork. It does not change
the published DecBench metric, dataset, or leaderboard.

The objective is to remove `pyjoern` and Joern completely from the maintained
code, dependency graph, runtime, tests, documentation, and generated artifacts
of `mjbommar/decbench`, and to use Cindergraph as the only source-C CFG
extractor used by GED. This is a fork policy, not a proposed change to the
upstream DecBench benchmark.

The fork will not silently route unsupported input back to Joern. Cindergraph
does not currently support C++, so `.ii` inputs will have an explicit
`unsupported-language` CFG outcome and GED will abstain. Type and byte-match
metrics remain available because they do not consume source CFGs. Historical
Joern-backed results remain immutable labelled data, not results reproducible
from the fork's current dependency set.

The change is narrower than replacing Joern as a code-property-graph system.
DecBench uses `pyjoern` only to obtain per-function directed CFG topology with
entry and exit roles. GED does not consume Joern statements, labels, types,
ASTs, DDGs, or query results.

## Current constraints

1. `decbench/utils/cfg.py` imports `pyjoern.parse_source` directly for both
   preprocessed source and decompiler output.
2. Source CFGs come exclusively from compiler-produced `.i` or `.ii` files.
   Translation-unit ownership, optimization level, and DWARF declaration-file
   selection are part of the scoring contract and must remain unchanged.
3. Cindergraph supports C, including damaged and decompiler-shaped C. It does
   not claim C++ support. The fork will fail closed for `.ii` CFG extraction
   and record an explicit unsupported-language abstention.
4. DecBench's Joern-specific degeneracy test inspects `Nop` statements. A
   Cindergraph parity node has no statements, so blindly reusing that test
   would incorrectly drop real one-block functions from the GED denominator.
5. NetworkX remains necessary at the current GED boundary. Replacing Joern
   does not by itself remove NetworkX, NumPy, SciPy, or `cfgutils`.
6. Changing the frontend can change graph shape and the score denominator.
   Cindergraph-backed GED is a distinct metric provenance and must not be
   presented as directly interchangeable with historical Joern-backed GED.

## Target architecture

### Provider-neutral record

Introduce a provider-independent record before constructing NetworkX graphs:

```python
@dataclass(frozen=True)
class ExtractedCfg:
    nodes: tuple[int, ...]
    edges: tuple[tuple[int, int], ...]
    entry: tuple[int, ...]
    exit: tuple[int, ...]
    degenerate: bool

@dataclass(frozen=True)
class CfgExtraction:
    functions: dict[str, ExtractedCfg]
    provider: str
    provider_version: str
    language: Literal["c", "c++"]
    diagnostics: tuple[CfgDiagnostic, ...]
    preprocessing: PreprocessingEvidence | None
```

The serialized topology is the durable contract. A single adapter converts it
to the node objects and `networkx.DiGraph` instances consumed by GED. Graph
attributes should retain `degenerate`, provider identity, language, and
diagnostic counts for compatibility with code that still receives a graph.

### Extractor interface

```python
class CfgExtractor(Protocol):
    name: str
    version: str
    supported_languages: frozenset[str]

    def extract_source(self, path: Path, text: str, language: str) -> CfgExtraction: ...
    def extract_decompiled(self, text: str, language: str = "c") -> CfgExtraction: ...
```

Implement only `CindergraphCfgExtractor`, using Cindergraph's serialized parity
CFG surface for C and its decompiler-oriented preprocessing/evidence API for
generated C. Keeping an internal extractor interface is still useful: it
isolates graph construction from pipeline orchestration and makes the data
contract testable, but it is not a runtime provider-selection feature.

There will be no `joern` provider, `auto` mode, Joern fallback, or `pyjoern`
extra. A C++ request returns a typed unsupported-language extraction outcome;
it must never look like a parser failure or an empty C translation unit.

## Implementation phases

### Phase 1: freeze the existing contract

Add fixture-backed tests before refactoring:

- ordinary branch, loop, switch, early return, goto, computed goto, and
  one-block functions;
- declaration-only and empty inputs;
- duplicate function names across translation units;
- `.i` system-header stripping and `.ii` suffix/language selection;
- decompiler sanitization and local macro expansion;
- parser failure, partial recovery, invalid UTF-8, and timeout behavior;
- source ownership selection and cross-TU fallback;
- serialized CFG round-trip with entry, exit, and degeneracy preserved.

Before deleting the dependency, capture the minimum topology fixtures needed
to prove the migration. Treat them as historical-provider observations, not
universal expected semantics. Tests in the final tree must not import, invoke,
download, or detect Joern.

### Phase 2: extract the provider boundary

Create `decbench/cfg/` with extraction models, NetworkX conversion, and the
Cindergraph extractor. Keep compatibility wrappers in `decbench/utils/cfg.py`
only while migrating call sites, then remove Joern-shaped interfaces that are
not part of the fork's public API.

Move provider-independent preprocessing decisions out of Joern-named helpers.
Do not duplicate Cindergraph's decompiler normalization inside DecBench. The
provider result must report whether preprocessing succeeded, failed, timed out,
or was unnecessary.

Replace statement-based degeneracy inference with Cindergraph's explicit
serialized field.

### Phase 3: thread configuration through every route

Add an explicit CFG extraction policy/version to `PipelineConfig`; do not add a
provider selector for an implementation the fork does not support. Thread the
Cindergraph extractor and typed extraction outcomes through:

- live evaluation;
- `PipelineExecutor`;
- `scripts/run_benchmark.py` and `scripts/reeval_ged.py`;
- external eval-kit ingestion;
- source-CFG dataset export and materialized reload;
- parse-health measurement and small/smoke drivers.

Workers should construct the in-process extractor after `spawn`; native
extension state must not be initialized in the parent and inherited by a
worker.

### Phase 4: provenance and cache separation

Persist at least:

- provider name and version;
- Cindergraph package version and CFG schema version;
- source language;
- preprocessing outcome;
- parser diagnostic count and partial-recovery flag;
- extraction-policy version.

Include extractor identity, version, language, preprocessing policy, and graph
serialization in the GED cache input. Bump `GEDMetric.cache_version` because
the scoring input and denominator policy change.

Source-CFG JSON should replace the ambiguous `"generator": "pyjoern"` string
with a versioned Cindergraph object while retaining read-only,
backward-compatible loading of old artifacts. Finalization must reject a result
tree that mixes Joern-backed and Cindergraph-backed CFGs within a supposedly
homogeneous comparison.

### Phase 5: differential validation

Before removal, run Cindergraph and the pinned historical Joern environment
over the same fixed populations:

1. checked-in valid C fixtures;
2. compiler-produced `.i` files at each optimization level;
3. captured decompiler outputs before and after existing DecBench cleanup;
4. controlled broken/damaged C;
5. pathological large CFGs and obfuscated C.

For every function record recovery, node/edge counts, entry/exit roles,
degeneracy, role-preserving isomorphism, VJ-GED, diagnostics, elapsed time, and
peak RSS. Classify every denominator difference. Joern is a historical
reference, not a correctness oracle; non-isomorphic graphs require source-level
adjudication or remain explicitly unresolved.

Acceptance gates:

- no Joern import, process, download, environment variable, or fallback;
- no genuine one-block definition classified as degenerate;
- no Joern-backed source graph paired with a Cindergraph-backed decompiler
  graph within one GED value;
- source ownership and optimization-level isolation unchanged;
- all previously scorable C functions either remain scorable or have a
  classified, recorded exclusion;
- C++ produces an explicit unsupported-language GED abstention while its
  non-CFG metrics continue normally;
- deterministic serialized output across repeated processes;
- full unit suite, lint, formatting, and typing gates pass.

### Phase 6: dependency and documentation cutover

After validation:

- make `cindergraph[graphs]` a normal dependency of the fork;
- delete `pyjoern` from all dependency groups and lockfiles;
- delete Joern installation, repair, environment-variable, subprocess, and
  troubleshooting paths;
- ensure a clean environment cannot download or invoke Joern transitively;
- document that the C score series is Cindergraph-backed and is not the
  historical Joern series;
- rename Joern-specific site text and parse-health fields to Cindergraph or
  frontend-neutral terminology;
- display extractor provenance in reports and exported dataset metadata;
- preserve historical Joern datasets as labelled legacy inputs, without
  claiming the current fork can regenerate them.

Do not update published scores or the public site as part of the provider
implementation. That is a separate, human-reviewed publication decision.

## File-level work map

| Area | Expected changes |
| --- | --- |
| `decbench/utils/cfg.py` | Compatibility wrappers; retain generic source cleanup only |
| `decbench/cfg/` | Models, extractor contract, Cindergraph integration, NetworkX conversion |
| `decbench/pipeline/evaluate.py` | Use Cindergraph for both sides of C GED; typed C++ abstention |
| `decbench/pipeline/executor.py` | Configuration propagation and fail-closed validation |
| `decbench/metrics/ged.py` | Explicit degeneracy metadata, cache-version bump, provenance metadata |
| `decbench/publish/cfg_export.py` | Versioned generator metadata and serialized degeneracy |
| `decbench/pipeline/materialized.py` | Backward-compatible schema loading and provenance checks |
| `decbench/cli.py` | Accurate C-only GED help and unsupported-language reporting |
| `scripts/` | Cindergraph extraction, neutral naming, one-time differential audit command |
| `tests/` | Contract, provider, routing, provenance, cache, and differential fixtures |
| `docs/` and rendering content | Methodology, installation, comparability, and limitations |
| `pyproject.toml` and lockfiles | Cindergraph normal dependency; remove `pyjoern` entirely |

## Suggested increments

1. Extraction record and round-trip tests, with no scoring behavior change.
2. Cindergraph C extractor plus degeneracy, diagnostic, and C++-abstention tests.
3. Pipeline integration and strict language routing.
4. Artifact provenance, cache separation, and mixed-generation rejection.
5. Fixed-population one-time Joern differential report and denominator audit.
6. Delete every runtime/test/documentation dependency on Joern and `pyjoern`.
7. Rebuild the lockfile in a clean environment, run the full suite, and prove
   no Joern artifact is installed or executed.

Each increment should be reviewable independently. No benchmark publication,
upstream issue, comment, or pull request should be created autonomously.
