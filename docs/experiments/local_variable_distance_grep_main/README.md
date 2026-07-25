# Local-variable edit distance: `grep::main` proof

This is an experimental, unregistered metric. Matching never uses variable names.
Arguments are matched by ABI position; unambiguous stack slots are locked after
frame-offset calibration; remaining variables are peeled by inverse-frequency
weighted address overlap.

## Result

| quantity | value |
|---|---:|
| source-owned DWARF variables | 38 |
| observable source variables | 38 |
| IDA variables | 140 |
| accepted matches | 34 |
| unresolved source variables | 4 |
| unmatched IDA variables | 106 |
| LVED | 110 |
| recovery accuracy | 0.382 |
| calibrated stack shift | -528 |
| IDA mapped pseudocode lines | 536 |

LVED is `|source| + |decompiled| - 2|matches|`; accuracy is
`2|matches| / (|source| + |decompiled|)`. Source variables with neither
compiled-use addresses nor stack/argument evidence are reported separately.

## Independently inspectable oracle checks

| source | expected IDA | actual | pass |
|---|---|---|---|
| `argc` | `a1` | `a1` | yes |
| `argv` | `a2` | `a2` | yes |
| `keycc` | `v131` | `v131` | yes |
| `keyalloc` | `v132` | `v132` | yes |
| `default_context` | `v133` | `v133` | yes |
| `filename_option` | `v127` | `v127` | yes |
| `num_operands` | `v59` | `v59` | yes |
| `psize` | `v61` | `v61` | yes |

Negative oracle pairs are also rejected: `num_operands ↛ v61`, `psize ↛ v59`.

Direct source-line and IDA-line address checks:

| evidence | addresses | pass |
|---|---|---|
| source num_operands | 0x5ddf, 0x5df6, 0x5e23, 0x5e9b, 0x5e9d | yes |
| source psize | 0x5e1e, 0x5e29, 0x5e2e, 0x5e31, 0x5e35, 0x5e3f, 0x5e42, 0x5e4f | yes |
| IDA v59 overlap | 0x5df6, 0x5e9b, 0x5e9d | yes |
| IDA v61 overlap | 0x5e29, 0x5e2e, 0x5e31, 0x5e35, 0x5e3f, 0x5e42, 0x5e4f | yes |

The oracle names are used only after matching to evaluate the result.
`num_operands ↔ v59` and `psize ↔ v61` are the register-only proof cases;
the earlier rows are independently checkable from DWARF and IDA stack comments.

## Accepted matches

| stage | source | IDA | score | shared addresses |
|---|---|---|---:|---|
| argument | `argc` | `a1` | 1.000 | 0x5df6, 0x5fbd, 0x5fc1 |
| argument | `argv` | `a2` | 1.000 | 0x5ea3, 0x5eaa, 0x5eaf, 0x5fdc |
| overlap | `matcher` | `v123` | 0.690 | 0x5131, 0x53b7, 0x53bb, 0x53c2, 0x53c7, 0x53d0, 0x53d4, 0x53db |
| overlap | `opt` | `v7` | 0.486 | 0x51d7, 0x51dd, 0x51e3, 0x51ea, 0x51ec, 0x51f0, 0x51f3, 0x5206 |
| overlap | `prev_optind` | `v119` | 0.536 | 0x5154, 0x5271, 0x5275, 0x5864 |
| overlap | `last_recursive` | `v126` | 0.901 | 0x5129, 0x5271, 0x5275, 0x5868, 0x586d, 0x6034, 0x603b, 0x603d |
| overlap | `fp` | `v15` | 0.770 | 0x568d, 0x56fb, 0x5700, 0x570e, 0x573f, 0x5743, 0x5882, 0x5889 |
| overlap | `eolbytes` | `v139` | 0.750 | 0x5d9c, 0x5d9f, 0x5da4, 0x5db3, 0x5dba, 0x5dca, 0x5dd1, 0x5dd9 |
| overlap | `num_operands` | `v59` | 0.500 | 0x5df6, 0x5e9b, 0x5e9d |
| overlap | `psize` | `v61` | 0.683 | 0x5e29, 0x5e2e, 0x5e31, 0x5e35, 0x5e3f, 0x5e42, 0x5e4f |
| overlap | `files` | `v112` | 0.562 | 0x6718, 0x671d, 0x6724, 0x6726, 0x672b, 0x672d, 0x6732, 0x6735 |
| overlap | `status` | `v65` | 0.385 | 0x5eb6, 0x5ebc, 0x5ec3, 0x5f36, 0x5f3a |
| overlap | `cc` | `v34` | 0.756 | 0x5797, 0x579a, 0x57a4, 0x57a7, 0x57aa, 0x57af, 0x57e5, 0x57f0 |
| overlap | `shortage` | `v35` | 0.737 | 0x57b9, 0x57be, 0x57c3, 0x57c9, 0x57cd, 0x57d9, 0x57de |
| overlap | `keyend` | `v32` | 0.462 | 0x57e5, 0x57f0, 0x5806 |
| overlap | `err` | `flags` | 0.900 | 0x573d, 0x5749, 0x574b, 0x58a4, 0x58a9, 0x58ab, 0x66f2, 0x66f9 |
| overlap | `shortage` | `i` | 0.636 | 0x56c0, 0x56c3, 0x56c6, 0x56ca, 0x56cd |
| overlap | `cmd` | `v11` | 0.426 | 0x5228, 0x5238, 0x523e, 0x5245, 0x5247, 0x6458, 0x645b |
| overlap | `cmd` | `v16` | 0.550 | 0x54b3, 0x54c3, 0x54ca, 0x54d0, 0x54d5, 0x54dc, 0x54df, 0x54e4 |
| overlap | `pat` | `v71` | 0.667 | 0x5fd7, 0x5fdc, 0x5fe0, 0x5fe2, 0x5fe5, 0x5fe7, 0x5fe9, 0x5fed |
| overlap | `skip_bs` | `v70` | 0.429 | 0x5ff0, 0x5ff4, 0x5fff |
| overlap | `patlen` | `v72` | 0.889 | 0x600b, 0x6010, 0x6013, 0x601a, 0x601c, 0x6021, 0x6025, 0x602a |
| overlap | `userval` | `v85` | 0.807 | 0x625c, 0x6263, 0x6268, 0x626b, 0x626e, 0x6270, 0x6273, 0x6275 |
| overlap | `q` | `j` | 0.818 | 0x6278, 0x627b, 0x627d, 0x6287, 0x628b, 0x628d, 0x6291 |
| overlap | `stdin_only` | `v63` | 0.211 | 0x6048, 0x604f |
| stack | `keys` | `src` | 1.000 | 0x5139, 0x5142, 0x5751, 0x5756, 0x5758, 0x575d, 0x5763, 0x576d |
| stack | `keycc` | `v131` | 1.000 | 0x503e, 0x56a3, 0x56a8, 0x56ad, 0x56b0, 0x5751, 0x5756, 0x5758 |
| stack | `keyalloc` | `v132` | 1.000 | 0x5047, 0x5113, 0x56bb, 0x56c0, 0x56c3, 0x56c6, 0x56ec, 0x57a7 |
| stack | `default_context` | `v133` | 1.000 | 0x5081, 0x542f, 0x5436, 0x543b, 0x5ce1, 0x5ce6, 0x5ced, 0x5cf2 |
| stack | `filename_option` | `v127` | 1.000 | 0x5103, 0x58b0, 0x5dfc, 0x5e01, 0x5e07, 0x5e0a, 0x5f4e, 0x5f52 |
| stack | `tmp_stat` | `buf` | 1.000 | 0x5f5c, 0x5f64, 0x5f69, 0x5f6c, 0x5f71, 0x5f73, 0x5f75, 0x5f7c |
| stack | `match_size` | `v134` | 1.000 | 0x5de3, 0x5de6 |
| stack | `newkeycc` | `v130` | 1.000 | 0x5768 |
| stack | `null_stat` | `v137` | 1.000 | 0x650e, 0x6516, 0x651d, 0x6522, 0x6524, 0x6526, 0x652e, 0x6536 |

## Unresolved source variables

| source | leading candidates |
|---|---|
| `possibly_tty` | `v40` (0.857), `v100` (0.842) |
| `cc` | `v27` (0.413), `v23` (0.408), `i` (0.319) |
| `cmd` | `v19` (0.436), `v20` (0.436) |
| `cwd_only` | `v63` (0.111) |

## Stack aliases deliberately not treated as exact

| IDA stack offset | sizes | aliases |
|---:|---:|---|
| 16 | [4, 8] | `streamb`, `stream`, `streama`, `streamc` |
| 24 | [4, 8] | `v119`, `v120`, `v121` |
| 64 | [8] | `v128`, `v129` |

## Negative controls

- Renaming every source and IDA variable leaves all pairs unchanged: `True`.
- Moving IDA address sets into a disjoint address space changes overlap matches from `23` to `0`.
- Injecting one fake IDA local changes LVED by `1`.

## Artifact checks

- Supplied/generated IDA text similarity: `0.963`.
- Supplied IDA declaration names recovered by the live extraction: `1.000` (140/140).
- Every emitted address lies inside `main` and on a decoded instruction: `True`.
- The IDA input contains no debug or static symbol-table sections: `True`.
- The preprocessed fixture contains the expected logical `main`: `True`.

The source use sets come from identifier tokens on source lines expanded to
instruction starts through DWARF line data. DWARF location lists are used only
for storage/lifetime constraints; treating their full ranges as uses would make
long-lived variables overlap nearly everything.
This first prototype uses token-boundary source occurrences; an AST-backed
identifier resolver is the main hardening step before metric registration.

Regenerate with:

```bash
python scripts/demo_local_variable_distance.py --check
```
