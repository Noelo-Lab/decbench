# Coreutils O2 local-variable correspondence experiment

Run date: 2026-07-25 (UTC)

## Scope

This experiment separates two questions:

1. How many source variables do IDA and Ghidra recover under the proposed
   local-variable edit-distance (LVED) correspondence?
2. When the correspondence algorithm accepts a pair, how often is that pair
   semantically valid?

LVED recovery is not matcher precision. The realistic lane uses stripped
binaries; the debug-visible lane is only a blinded-name matcher calibration.

## Corpus and tools

- GNU coreutils 9.1, x86-64
- GCC 11.4.0, `-O2 -g -fno-builtin -save-temps=obj`
- IDA 9.2 SDK (`920`)
- Ghidra 12.1
- 109/109 ELF binaries compiled successfully in 172.7 seconds; 135
  preprocessing units saved
- only `O2` was built
- 218/218 stripped binary/backend jobs completed in approximately 214 seconds
- checkpoint SHA-256:
  `3be4d8b00184ab9e0574369fb0b7b6b1c576bb3a617f3e919b52ff800622dd45`

The backend-independent target universe is defined by an address-bearing DWARF
function whose path-qualified compilation unit matches the primary line marker
of exactly one saved `.i` unit. This yields 1,011 `src/*` functions. The build
also contains 2,842 linked `lib/*` compilation units (8,583 function instances)
without matching saved preprocessing units; they are explicitly out of scope
instead of being attributed by basename. The former basename rule would also
have admitted 478 checkpoint-only functions and is quarantined as invalid.

The reported sample is the lowest 100 functions under the frozen
`sha256-rank-v1` seed `coreutils-lved-v1`: 26 tuning and 74 held out. Thresholds
were frozen at `min_overlap=0.1` and `ambiguity_margin=0.03`. No threshold was
changed after viewing held-out results.

## Realistic stripped lane

Every sampled source function extracted successfully. One function,
`cksum::md5_sum_stream`, is missing from both decompiler checkpoint outputs;
one additional function is missing from IDA. Missing backend results remain in
the source denominator.

| Set | Backend | Functions ok | Accepted / observable source | Coverage | Abstention | LVED recovery |
|---|---:|---:|---:|---:|---:|---:|
| All | Ghidra | 99/100 | 376/448 | 83.93% | 16.07% | 46.51% |
| All | IDA | 98/100 | 378/448 | 84.38% | 15.62% | 22.66% |
| Held out | Ghidra | 73/74 | 268/327 | 81.96% | 18.04% | 42.91% |
| Held out | IDA | 72/74 | 269/327 | 82.26% | 17.74% | 19.15% |

IDA's much lower LVED recovery despite similar source coverage is caused by
its larger decompiler-variable set, which LVED counts as unmatched insertions.
It is not evidence that the accepted IDA pairs are less precise.

Function-macro results and function-clustered bootstrap intervals are:

| Set | Backend | Macro coverage (95% CI) | Macro LVED recovery (95% CI) |
|---|---:|---:|---:|
| All | Ghidra | 87.56% (82.71–91.99) | 54.16% (48.49–59.95) |
| All | IDA | 85.99% (80.51–90.85) | 46.46% (40.26–52.22) |
| Held out | Ghidra | 86.15% (80.12–91.36) | 52.53% (45.30–59.23) |
| Held out | IDA | 84.19% (77.21–90.12) | 45.43% (38.13–52.15) |

## Blinded debug-visible calibration

IDA and Ghidra analyzed the corresponding unstripped binaries. All source and
decompiler variable names were replaced with opaque aliases before matching.
After matching, unique nonsynthetic retained names were used as a conservative
oracle. All 200 function/backend rows completed, and the imported 26/74 split
was preserved exactly.

| Set | Backend | Accepted | Correct | Wrong | Oracle unknown | Decidable precision | Decidable error | Oracle retention | Oracle recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| All | IDA | 403 | 256 | 0 | 147 | 100% | 0% | 60.94% | 93.77% |
| All | Ghidra | 398 | 240 | 0 | 158 | 100% | 0% | 55.36% | 96.77% |
| Held out | IDA | 291 | 185 | 0 | 106 | 100% | 0% | 61.47% | 92.04% |
| Held out | Ghidra | 292 | 169 | 0 | 123 | 100% | 0% | 53.82% | 96.02% |

The unknown-bounded accepted-pair error intervals are therefore 0–36.48% for
IDA and 0–39.70% for Ghidra on all functions, and 0–36.43% / 0–42.12% on held
out functions. These wide worst-case bounds reflect selective name retention,
not observed errors. On the stricter common retained-name subset, the held-out
upper bounds are 1.81% for IDA and 0.60% for Ghidra.

Selectivity is most severe for the novel overlap stage: only 14/158 accepted
IDA overlap pairs and 8/149 accepted Ghidra overlap pairs are name-decidable.
The calibration's 100% decidable precision therefore cannot stand alone as an
accuracy claim; the stripped semantic audit is required.

This lane is not a realistic decompiler recovery measurement: debug metadata
can influence variable construction, and the exact-name oracle is weak for
synthetic, missing, duplicated, split, or merged variables.

## Independent stripped semantic audit

Three isolated reviewers labeled all 896 source-variable/backend cases in
three disjoint shards. Reviewers saw source context and pseudocode with
HMAC-keyed opaque decompiler-variable identifiers, but not matcher targets,
addresses, scores, stages, candidates, partitions, or the private join. The
merge accepted 804 `mapped`, 90 `none_recovered`, and 2 `oracle_unknown`
labels; confidence was 833 high, 61 medium, and 2 low. Every rationale was
case-specific.

An accepted edge is valid when it is a reviewer-selected semantic relation.
This includes valid split, merge, and many-to-many edges at `-O2`. The
one-to-one-only number is reported separately and should not be treated as the
primary matcher accuracy.

| Set | Backend | Accepted | Valid / decidable | Wrong | Unknown | Valid-edge precision (95% CI) | Decidable error | Error bounds |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All | Ghidra | 376 | 338/376 | 38 | 0 | 89.89% (86.18–93.42) | 10.11% | 10.11–10.11% |
| All | IDA | 378 | 328/377 | 49 | 1 | 87.00% (83.73–90.12) | 13.00% | 12.96–13.23% |
| Held out | Ghidra | 268 | 236/268 | 32 | 0 | 88.06% (83.33–92.56) | 11.94% | 11.94–11.94% |
| Held out | IDA | 269 | 229/268 | 39 | 1 | 85.45% (81.23–89.43) | 14.55% | 14.50–14.87% |

Combined across backends, valid-edge precision is 666/753 = **88.45%**
(95% clustered CI 85.53–91.27), with a decidable error of **11.55%**
(8.73–14.47). On held-out functions it is 465/536 = **86.75%**
(83.01–90.22), with a decidable error of **13.25%** (9.78–16.99).
The latter is the primary frozen held-out estimate of matcher accuracy/error.
The single accepted unknown makes the combined all-function worst-case error
interval 11.54–11.67% and the held-out interval 13.22–13.41%.

The same frozen audit can be expressed as a strict candidate-edge confusion
table. For each decidable source-variable case, every distinct
reviewer-visible source-variable–decompiler-variable alias pair is one
evaluation edge:

- **TP:** the matcher and reviewer both selected the edge.
- **FP:** the matcher selected the edge; the reviewer did not.
- **FN:** the reviewer selected the edge; the matcher did not.
- **TN:** neither selected the pair.

| Scope | Decidable pairs | TP | FP | FN | TN | Unknown excluded (cases / pairs) | Precision | Edge recall | Edge F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Held out · combined | 22,757 | 465 | 71 | 271 | 21,950 | 2 / 809 | 86.75% | 63.18% | 73.11% |
| Held out · Ghidra | 6,459 | 236 | 32 | 134 | 6,057 | 1 / 7 | 88.06% | 63.78% | 73.98% |
| Held out · IDA | 16,298 | 229 | 39 | 137 | 15,893 | 1 / 802 | 85.45% | 62.57% | 72.24% |
| Overall · combined | 26,730 | 666 | 87 | 316 | 25,661 | 2 / 809 | 88.45% | 67.82% | 76.77% |
| Overall · Ghidra | 8,079 | 338 | 38 | 152 | 7,551 | 1 / 7 | 89.89% | 68.98% | 78.06% |
| Overall · IDA | 18,651 | 328 | 49 | 164 | 18,110 | 1 / 802 | 87.00% | 66.67% | 75.49% |
| Tuning · combined | 3,973 | 201 | 16 | 45 | 3,711 | 0 / 0 | 92.63% | 81.71% | 86.83% |
| Tuning · Ghidra | 1,620 | 102 | 6 | 18 | 1,494 | 0 / 0 | 94.44% | 85.00% | 89.47% |
| Tuning · IDA | 2,353 | 99 | 10 | 27 | 2,217 | 0 / 0 | 90.83% | 78.57% | 84.26% |

The held-out rows are the primary unbiased results; overall rows include the
tuning partition and are descriptive. Split and many-to-many relations can
produce one TP plus additional FNs because the current matcher accepts at most
one edge per source variable and is globally one-to-one. A merge can make the
same decompiler carrier a positive edge for several source-variable cases.

Ordinary candidate-pair accuracy, specificity, and NPV are intentionally not
reported. The large number of irrelevant TN pairs is dominated by each
decompiler's variable-set size—IDA exposes substantially more pairs than
Ghidra—so those quantities would look artificially high and are not suitable
for cross-backend comparison. Precision, edge recall, and edge F1 are the
meaningful pair-level summaries. The report generator computes these counts
directly and records excluded oracle-unknown pair counts separately.

The stage breakdown identifies where the errors occur:

| Set | Stage | Accepted | Valid / decidable | Wrong | Unknown | Valid-edge precision |
|---|---:|---:|---:|---:|---:|---:|
| All | Argument index | 390 | 387/390 | 3 | 0 | 99.23% |
| All | Address overlap | 298 | 213/297 | 84 | 1 | 71.72% |
| All | Stack offset | 66 | 66/66 | 0 | 0 | 100% |
| Held out | Argument index | 270 | 267/270 | 3 | 0 | 98.89% |
| Held out | Address overlap | 219 | 150/218 | 68 | 1 | 68.81% |
| Held out | Stack offset | 48 | 48/48 | 0 | 0 | 100% |

All 84 all-function overlap errors are local variables. Thus the experiment
validates argument-index and stack-offset matching, but the current overlap
threshold is not sufficiently selective. Frozen score bins support the same
conclusion: all-function valid-edge precision rises from 33.33% below score
0.25 to 99.34% at score at least 0.99. Among matches with a defined runner-up
gap, precision is only 11.11% for gaps 0.03–0.05 and 84.55% at gaps at least
0.25. These bins are diagnostic; no post-hoc threshold is substituted into
the held-out headline.

The source-centered oracle also permits a semantic decompiler-recovery view,
separate from symmetric LVED:

| Set | Backend | Semantic source recovery | Any-neighbor source hit | Oracle-edge recall | Full-relation recall | End-to-end accepted recovery |
|---|---:|---:|---:|---:|---:|---:|
| All | Ghidra | 411/447 = 91.95% | 338/411 = 82.24% | 338/490 = 68.98% | 309/411 = 75.18% | 338/447 = 75.62% |
| All | IDA | 393/447 = 87.92% | 328/393 = 83.46% | 328/492 = 66.67% | 275/393 = 69.97% | 328/447 = 73.38% |
| Held out | Ghidra | 297/326 = 91.10% | 236/297 = 79.46% | 236/370 = 63.78% | 213/297 = 71.72% | 236/326 = 72.39% |
| Held out | IDA | 284/326 = 87.12% | 229/284 = 80.63% | 229/366 = 62.57% | 188/284 = 66.20% | 229/326 = 70.25% |

These ratios exclude the two `oracle_unknown` cases; end-to-end denominators
retain missing backend results as `none_recovered`. “Any-neighbor” counts a
source variable when the matcher finds at least one selected semantic
neighbor. Oracle-edge recall requires every selected edge separately, while
full-relation recall requires the complete selected-neighbor set; these are
lower because the current matcher is one-to-one and cannot fully express a
split relation.

This semantic recovery is much higher than LVED recovery because LVED also
penalizes every extra decompiler temporary as an insertion. The semantic
oracle found substantial optimized topology: Ghidra had 30 split, 47 merge,
and 9 many-to-many source relations; IDA had 53 split, 28 merge, and 13
many-to-many relations. Consequently, strict one-to-one accepted precision
is only 76.86% for Ghidra and 70.82% for IDA even though many of those
non-one-to-one edges are semantically valid.

The checkpoint did not preserve per-PC decompiler register/stack storage, so a
fully independent storage-location oracle cannot be reconstructed. The
semantic audit consequently permits `oracle_unknown` for optimized folding,
coalescing, and insufficient pseudocode evidence. The original scorer
aggregate also did not record scorer-time hashes for every binary, source, and
`.i` file. The audit records current hashes and requires exact reconstructed
structural evidence, including dropped instruction addresses, to equal the
scorer rows; this is strong evidence against drift but cannot prove that
reviewer-visible source text is byte-identical to the earlier scorer-time
text.

## Controls and reproducibility

All scorer and calibration result sets passed:

- name-renaming invariance
- disjoint-address overlap is zero
- one fake decompiler local increases LVED by one
- every retained address is a decoded instruction in the function
- stripped inputs contain neither debug sections nor `.symtab`
- repeated runs produce identical accepted pair sets

The canonical scorer rerun was byte-identical to the validated candidate:

- scorer JSONL:
  `2d0f3047e9b89ef8d8b60ef1bb7f221512a14cd58aac31afb2468c93d9e25420`
- aggregate JSON:
  `d6d156c723663b8a1d491694f72e1b2488fee3142a8da66ec552b6847d09fd4c`
- run binding:
  `bed0ec8b5a866edabff44306ce620e7ee0095f7b44a95c374914069f9b8f8084`

The completed semantic-audit artifacts are:

- package manifest:
  `a33d404abedb05db06c030b36c72e9cc7be4052440a0a30f5e7b0f3a51a1b4f2`
- merged labels:
  `d47d113ec9843bdf0175f83c02073ca80fb8f6e5398d1afe35b8791717657281`
- joined semantic results:
  `b60039c20435e37917a046249791d61ff1ef8bd7763e781c01a37f480aef776b`
- semantic report:
  `416810495abdd1476612f58f327b2f48884a6dbdc452236f87b8de9f4e05de38`

The audit package and completed merge validate with 896/896 cases. The focused
scorer, calibration, and semantic-audit suite passes 36 tests with one
environment-dependent skip; Ruff, Black, and `git diff --check` are clean.
