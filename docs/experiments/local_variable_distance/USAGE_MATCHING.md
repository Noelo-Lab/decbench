# Usage-based local-variable correspondence

Status: the matcher and feature extractor are used by production `type_match`;
the frozen semantic audit remains an experimental development measurement.
Changing correspondence behavior requires a `type_match` cache-version bump.

## Motivation

PR #48 originally matched source and decompiler variables with instruction
addresses obtained from source line tables and native decompiler token maps.
That remains the highest-quality evidence when a backend exposes it, but many
decompilers and code-producing LLMs return only C-like text.

The usage matcher adapts the design principle from the
[discovRE paper](https://www.ndss-symposium.org/wp-content/uploads/2017/09/discovre-efficient-cross-architecture-identification-bugs-binary-code.pdf):
represent an entity with inexpensive, architecture-insensitive behavioral
features, retrieve plausible candidates, and abstain when the best assignment
is weak or ambiguous. This is an adaptation to variables in C syntax, not a
reimplementation of discovRE's binary-function matcher.

## Modes

`match_variables()` accepts three modes:

- `address` uses argument position, consensus-calibrated
  stack slots, then inverse-frequency-weighted address overlap. It is still the
  explicit ablation. Variables inferred only from pseudocode retain reliable
  ABI argument and explicit-stack anchors in this mode, but receive no inferred
  line-address or usage evidence.
- `usage` is the strict address-free ablation. It does not read instruction or
  source-line addresses, stack offsets, argument positions, declaration order,
  variable names, types, sizes, pointer depth, or cast target types.
- `address+usage` retains argument and unique-stack anchors, then jointly scores
  every residual candidate with address and usage evidence. It is a fused
  reranker, not an address-first fallback, so usage evidence can correct or
  veto a weak overlap edge.

The modes are deliberately explicit. In particular, `usage` does not quietly
receive easy argument-position matches; that would inflate an address-free
ablation with another backend-supplied identity channel.
Production `type_match` resolves its `auto` default to `address+usage`.

## Parsing and candidate discovery

Usage features are extracted with
[Tree-sitter](https://tree-sitter.github.io/tree-sitter/) and its C grammar.
Tree-sitter retains useful concrete-syntax subtrees in imperfect pseudocode,
including underneath parse-error nodes. If an output is only a statement/body
fragment and has no function-definition node, the extractor wraps the body in
a synthetic function and makes a best-effort second parse; multiple real
definitions remain an explicit abstention instead of guessing.

Source functions are indexed once per preprocessed C `.i` unit and selected
by exact function name, so macro-expanded behavior is analyzed without
reparsing the translation unit for every function. Raw C is a fallback when
the preprocessed definition cannot be selected. Checkpoint discovery still
collects both `.i` and `.ii` units as required by the main benchmark, but the
usage extractor deliberately emits no source usage features for C++ `.ii`
units; address mode remains available for them. C++ usage matching needs a
separate grammar and leakage audit.

Decompiler-provided `FunctionDecompilation.variables` remain authoritative.
When that list is empty, the extractor conservatively discovers formal
parameters and body-local declarators from the C syntax tree. It excludes
typedefs, block `extern` declarations, function prototypes, globals, member
names, labels, and direct callees. It does not invent candidates from
undeclared register-like identifiers. Repeated or shadowed declarations remain
in the candidate/edit-distance universe but are left featureless rather than
assigning one use bag to several variable identities.

This fallback changes only the experimental `VariableEvidence`; it does not
expand the persisted backend model or require every decompiler plugin to grow
a new mapping API.

## Feature vector

Each variable receives a sparse counted vector containing only usage context:

- generic read, write, and read/write roles;
- assignment, binary, unary, dereference, address-of, cast, field-base, and
  subscript-base/index roles;
- condition, loop, switch, `for`, and return-value context;
- direct call name, arity, argument position, indirect-callee use, and call
  return-target use;
- normalized integer literals and hashed string/character literals.

Commutative operand sides are normalized. Literals are attached only to a
variable's local operand relation, so a constant in another call argument does
not smear across every argument. Locally declared callees are emitted only as
generic indirect calls, and synthetic address-like function names are
normalized away. Decompiler pseudo-calls whose names encode byte/bit widths
(`__ROR8__`, `CONCAT71`, `SUB168`, byte/word extractors, and carry/borrow
helpers) are mapped to width-free operation families. Identifier nodes in
comments, strings, member-name position, and unevaluated `sizeof`/`alignof`
operands do not become uses.

Feature values are serialized only after extraction. The scorer then replaces
source and decompiler variable names with opaque aliases and removes the raw C,
while retaining the already name-free vector. Tests compare full-code alpha
renames and scan feature values for local spellings.

The exclusions around type information are load-bearing: the correspondence
is intended to support grading recovered variable types, so type spelling,
byte width, pointer depth, and cast target type would leak the answer being
graded. All production modes obey that rule end to end: names and sizes are
cleared before correspondence, and size-compatible matching is disabled.

## Similarity and assignment

For token count `c_t`, the matcher uses `x_t = log(1 + c_t)`. A token weight is
its fixed family reliability (3 for named calls and strings, 2 for structural
operations/control/literals, 1 for generic roles) divided by a log-scaled
within-function degree term. The pair score is weighted generalized Jaccard:

```text
sum_t weight_t * min(x_source_t, x_decompiled_t)
------------------------------------------------
sum_t weight_t * max(x_source_t, x_decompiled_t)
```

At least one shared non-generic context token is required. Qualified edges go
through the same deterministic mutual-best, bidirectional runner-up-margin
peeling as address overlap. Equal best vectors therefore abstain instead of
being resolved by name or declaration order.

In `address+usage`, address and usage scores are linearly combined when both
contexts exist. A genuinely absent channel leaves the available channel
unscaled; two present but contradictory channels retain the zero from the
contradicting side.

The fixed production policy is overlap threshold `0.10`, address ambiguity
margin `0.03`, usage threshold `0.15`, usage ambiguity margin `0`, combined
threshold `0.20`, combined ambiguity margin `0`, and address weight `0.50`.
Variable-size compatibility is always false.

## Reproducing the Coreutils comparison

First regenerate serialized feature evidence from the existing checkpoint;
this does not compile or decompile anything:

```bash
source /home/mahaloz/.virtualenvs/decbench/bin/activate

python scripts/score_local_variable_distance.py \
  --checkpoint results/lved_coreutils/checkpoints/coreutils.pkl \
  --results-root results/lved_coreutils \
  --optimization O2 \
  --decompiler ida \
  --decompiler ghidra \
  --sample-size 100 \
  --production-type-match-policy \
  --bootstrap-iterations 0 \
  --output /tmp/lved-features-scorer.jsonl \
  --report /tmp/lved-features-aggregate.json \
  --no-label-template
```

Then replay the fixed production policy against the unchanged completed audit
package:

```bash
python scripts/evaluate_local_variable_matchers.py \
  --scorer /tmp/lved-features-scorer.jsonl \
  --aggregate /tmp/lved-features-aggregate.json \
  --audit-package results/lved_coreutils/semantic_audit \
  --mode address \
  --mode usage \
  --mode address+usage \
  --bootstrap-iterations 2000 \
  --output /tmp/lved-mode-comparison.json
```

The evaluator rejects threshold tuning and size compatibility. It sends the
full production-retained DWARF denominator and full production decompiler
candidate set to the matcher before joining labels. Frozen-label metrics are
computed only where the old private identity map can classify the resulting
decision. New source cases and decisions selecting newly exposed candidates
are emitted as unlabeled blockers; no label is inferred. The canonical audit
package is never modified.

## Exact production-policy replay (2026-08-17)

The current replay used the same frozen 100 Coreutils O2 functions and the
same IDA/Ghidra checkpoint, but constructed the source denominator from the
variables retained by production TypeMatch, included unnamed decompiler
candidates, applied production binary shift hints, disabled size matching, and
ran the full candidate competition before looking up audit labels.

The frozen-label results below are conditional measurements, not full-universe
accuracy. They include only retained source cases whose resulting decision can
be represented by the immutable private audit map.

| Scope | Mode | Accepted | TP | FP | FN | Precision | Edge recall | Edge F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | `address` | 766 | 674 | 91 | 300 | 88.10% | 69.20% | 77.52% |
| Overall | `usage` | 339 | 266 | 73 | 708 | 78.47% | 27.31% | 40.52% |
| Overall | `address+usage` | 765 | 692 | 72 | 282 | 90.58% | 71.05% | 79.63% |
| Development held out | `address` | 550 | 473 | 76 | 257 | 86.16% | 64.79% | 73.96% |
| Development held out | `usage` | 242 | 180 | 62 | 550 | 74.38% | 24.66% | 37.04% |
| Development held out | `address+usage` | 549 | 488 | 60 | 242 | 89.05% | 66.85% | 76.37% |

On the held-out conditional subset, stacking changed precision by +2.89
percentage points (paired function-cluster bootstrap 95% CI +1.07 to +4.94),
edge recall by +2.05 points (+0.22 to +4.35), and F1 by +2.41 points (+0.99 to
+4.25), using 2,000 paired bootstrap iterations.

The validity audit is the more important result. Production retains 1,420
unique source variables in the sample: 487 have an address/ABI anchor, 237
have usable usage context, five are usage-only, and 928 have neither channel
but remain in the TypeMatch denominator. Only 440 retained identities overlap
the old audit, leaving 980 unique variables (1,957 source/backend cases)
without labels. Sixteen old audit cases are not retained by production because
they lack a gradable located type. Production also exposes 112 unnamed IDA
candidates across 72 function/backend groups. No evaluated mode selected one
of those new candidates for an old audited source, but the frozen oracle cannot
establish their relations or validate abstentions against them. A complete
production-universe accuracy claim therefore requires an audit extension.

Reproducibility anchors for this replay:

- scorer configuration schema: `lved-score-config-v3`
- production-policy scorer JSONL SHA-256:
  `b16711a3ed309dbb4e3d549a764eb192afe54676e1aec37d29a03e99fc6b6be7`
- scorer aggregate SHA-256:
  `77bba22dd01555843426006a3740759ff8f953dae0300477675710be4395c2ea`
- exact-policy comparison SHA-256:
  `b904f5ea861d4b45c79e78be9537996bb4c02c8aca212f72b33afde209ae063e`

## Historical common-universe evaluation (2026-08-11)

This historical run reused the frozen 100-function Coreutils sample
(26 tuning, 74 development held out), IDA 9.2 and Ghidra 12.1 outputs, and the
completed 896-case semantic audit. Source candidates were filtered to the
frozen address-observable audit universe *before* matching, so the 12 newly
usage-matchable source variables outside that universe neither received a
decision nor competed for a decompiler variable.

Parameters were selected only on the tuning partition. Strict `usage` chose
`min_usage_similarity=0.15` and margin `0`. `address+usage` chose
`min_combined_similarity=0.20`, usage margin `0`, and address weight `0.50`.
The address baseline remained frozen at overlap `0.10` and margin `0.03` and
reproduced all 754 legacy accepted edges exactly.

| Scope | Mode | Accepted | TP | FP | FN | Precision | Edge recall | Edge F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | `address` | 754 | 666 | 87 | 316 | 88.45% | 67.82% | 76.77% |
| Overall | `usage` | 492 | 368 | 124 | 614 | 74.80% | 37.47% | 49.93% |
| Overall | `address+usage` | 780 | 702 | 77 | 280 | 90.12% | 71.49% | 79.73% |
| Development held out | `address` | 537 | 465 | 71 | 271 | 86.75% | 63.18% | 73.11% |
| Development held out | `usage` | 334 | 243 | 91 | 493 | 72.75% | 33.02% | 45.42% |
| Development held out | `address+usage` | 562 | 496 | 65 | 240 | 88.41% | 67.39% | 76.48% |

On the held-out partition, stacking changed precision by +1.66 percentage
points (paired function-cluster bootstrap 95% CI -0.63 to +4.29), recall by
+4.21 points (+1.88 to +6.79), and F1 by +3.37 points (+1.72 to +5.37), using
2,000 paired bootstrap iterations. The stacked 780 overall decisions comprise
390 argument anchors, 66 stack anchors, 271 genuinely fused edges, 46
address-only residual edges, and 7 usage-only fallbacks.

Feature extraction covered 434/465 source variables; 411/465 had at least one
non-generic context and were usage-matchable. On successful backend rows,
3,954/4,058 decompiler-variable occurrences were usage-matchable. These IDA
and Ghidra checkpoints already have structured candidates, so this run tests
the address-free *matching signal* by ignoring mappings; it does not validate
candidate discovery on an actual map-less backend.

Reproducibility anchors:

- checkpoint SHA-256:
  `3be4d8b00184ab9e0574369fb0b7b6b1c576bb3a617f3e919b52ff800622dd45`
- feature scorer JSONL SHA-256:
  `5e0e9970c5ddbc0a459a6946ab273d6c25fe73cedc9e8df2399eb19b961df419`
- scorer aggregate SHA-256:
  `e60d8dbd16fc176e1c99694c3eb99d98d30506783d04930c0b690fd07250da48`
- mode-comparison report SHA-256:
  `640ed73748039facff23b73ac8ca6c5c1d46d783117cfeb91ac28635802724ca`
- audit labels SHA-256:
  `d47d113ec9843bdf0175f83c02073ca80fb8f6e5398d1afe35b8791717657281`
- parser versions: `tree-sitter==0.26.0`, `tree-sitter-c==0.24.2`

## Interpretation limits

The completed audit labels only the old address-observable source universe and
the old named decompiler-candidate catalog. It cannot supply full-denominator
recall for production TypeMatch, classify a decision to a newly included
unnamed candidate, or prove that an abstention is correct when such a candidate
was never shown to reviewers. The exact-policy report therefore separates
full-universe coverage from frozen-catalog label metrics and marks the latter
as conditional. It also is not a pristine confirmation set for the new method:
the old held-out report and labels already existed during development.

Optimized DWARF can make this gap much larger than a count of lexical variables
suggests. In the frozen sample, `b2sum:blake2b_compress` has one top-level DIE
covering `[0x4470, 0x5a50)`, but that DIE contains 384 inlined `rotr64`
instances. Production retains 625 located variable DIEs for the function; the
old non-inlined audit contains five. Those identities must remain in the
production denominator unless the metric's inlining policy itself is changed
and independently justified.

A confirmatory experiment should freeze this implementation and its
parameters, select the next disjoint stable-hash sample, define eligibility
independently of matcher mode, and expose only address-free reviewer shards
until all labels are merged. Testing IDA/Ghidra after clearing their mappings
simulates a map-less backend; generalization to LLM or other text-only output
needs an audit that actually includes those backends.
