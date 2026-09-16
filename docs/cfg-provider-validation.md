# Cindergraph CFG provider validation

The fork's GED frontend is Cindergraph 0.1.0 at commit
`cfdeaccce9f11e2e23fbbda506b1b59d5086ef73`. It is the only live CFG
provider. Historical DecBench results generated with another frontend remain
labelled historical data and are not silently combined with current results.

## Fixed-population differential evidence

The provider was validated before this cutover against the historical Joern
implementation on fixed, hashed populations. The complete report and raw
records live with Cindergraph so that the parser implementation, fixtures,
comparison harness, and adjudications remain versioned together:

- [DecBench-adjacent CFG comparison](https://github.com/mjbommar/cindergraph/blob/ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825/docs/benchmarks/joern-decbench-2026-09-15.md)
- [difference classification and remediation](https://github.com/mjbommar/cindergraph/blob/ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825/docs/benchmarks/joern-difference-roadmap-2026-09-15.md)
- [damaged-code and decompiler-output robustness](https://github.com/mjbommar/cindergraph/blob/ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825/docs/benchmarks/joern-cdt-robustness-2026-09-15.md)
- [IOCCC obfuscated-C comparison](https://github.com/mjbommar/cindergraph/blob/ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825/docs/benchmarks/ioccc-cfg-comparison-2026-09-15.md)

On 930 shared clean-C functions, the remediated comparison measured 894 exact
CFG matches and 36 classified differences, with zero provider failures. Every
remaining difference was individually adjudicated in the linked roadmap.
Cindergraph also recovered all 25 expected functions in the decompiler-dialect
population; the historical frontend recovered 16 after DecBench cleanup.

These measurements establish suitability for DecBench's narrow per-function
CFG role. They do not claim equivalence to a full code-property graph, semantic
correctness merely because two graphs agree, or C++ support. Cindergraph
currently treats `.ii` input as an explicit unsupported-language GED
abstention. Type and byte-match metrics do not depend on the CFG frontend and
continue normally.

## In-repository acceptance evidence

The fork protects the cutover with tests for:

- provider-neutral serialized topology and deterministic repeat extraction;
- entry, exit, and explicit degeneracy preservation through NetworkX conversion;
- genuine one-block functions remaining scoreable;
- typed C++ unsupported-language outcomes;
- source translation-unit ownership and cross-TU fallback;
- versioned generator metadata and rejection of mixed source-CFG generators;
- Cindergraph identity, schema, policy, preprocessing status, diagnostics, and
  recovery state in GED cache inputs.

The dependency lock pins the exact Cindergraph commit. A clean installation
contains no Joern package, service, download, or fallback path.
