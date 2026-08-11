# Changelog

Significant changes to DecBench that introduce or update results, which can be viewable on the website.

### 2026-08-08

- Update `Kuna` to version `v1.121`, which has changed its rank.
- Minor fix to GED correctness in [PR #57](https://github.com/Noelo-Lab/decbench/pull/57). Changes the scores of all decompilers on structure, but has largely maintained the same order.


### 2026-07-27

- Added a warning about LLM based results having bias, based on [Issue #43](https://github.com/Noelo-Lab/decbench/issues/43#issuecomment-5093320127) discussion and analysis.

### 2026-07-25

- Fixed a caching bug in `sample-set` that prevented Codex/CC from having 3 samples graded/shown in the UI. Their scores have changed slightly.
- External submission to DecBench are now open and can be done for closed source or private decompilers. See the [README note](https://github.com/Noelo-Lab/decbench#compete-externally) for how.

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
