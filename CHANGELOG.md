# Changelog

Significant changes to DecBench that introduce or update results, which can be viewable on the website.

### 2026-07-25

- External submissions: `decbench evalkit export` packages the frozen 250-function sample-set as an anonymized eval kit outside decompiler authors can score against, and `decbench evalkit ingest` brings their packaged results back as a new sample-set-only leaderboard column (see `docs/decompilers.md`).
- Repaired the sample-set to a true 250: 7 of the frozen picks were rows no decompiler could score (5 of them relabel-duplicate CRT/TLS-callback names with no DWARF anchor at all), so they were dead slots that scored for nobody. `scripts/export_sample_set.py --drop-unscoreable` drops them and refills their slots from the same category buckets, preserving every other pick verbatim. All 250 now resolve to real DWARF addresses across 224 binaries.

### 2026-07-24

- Updated `about` to include other related works and some limitations of the benchmark metrics.

### 2026-07-23

- DecBench v1.1
- Update `Kuna` to version `v1.0`, which have shifted optimized results.
- What was previously the `distance` page is now the `data` page and contains new info on LLM costs.
- Removed `mirai-win` target since it is not actually Windows, but just Linux binaries (which the benchmark already has).

### 2026-07-22

- **DecBench goes live** with support for 7 traditional decompilers, 2 LLMs (partial), and 3 defining metrics.
- An expanded evaluation of AI agents is planned after credits are secured for running those evaluations.
