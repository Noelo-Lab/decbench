# Changelog

Significant changes to DecBench that introduce or update results.

### 2026-07-23

- **Corrected the `optimized` scores after a silent data-loss regression.** Kuna
  had briefly dropped on the optimized set because a whole binary's
  optimized slice (betaflight, ~1700 perfect GED functions) fell out of the
  published data during a fragmented rebuild — the numbers were assembled from
  per-project checkpoints plus separate metric-overlay files, and a partial
  overlay silently wiped the slice with no error. The results pipeline now
  derives the published dataset through one guarded path
  (`decbench/results_store.py`) that always rebuilds from every project's
  checkpoint, merges the metric overlays per-slice (so a partial overlay can no
  longer erase data), and refuses any unexplained shrink in coverage. Kuna's
  optimized score is restored to its correct value.
- Removed the **mirai-win** malware target. Despite its name (from theZoo's
  "Win32.Mirai" directory), it was a second **Linux/ELF** Mirai variant built
  with gcc — duplicating the existing `mirai` target's coverage while implying
  Windows coverage the benchmark did not have. Its 141 function rows left every
  score, and its 3 sample-set functions were replaced by a deterministic top-up
  draw from the same categories (the other 247 sample-set picks are unchanged);
  the LLM backends were re-run on just the 3 replacements.
- Added a third LLM/coding-agent decompiler backend: **kimi-code** (Kimi Code
  CLI, default model `kimi-code/k3`), benchmarked on the sample-set slice like
  codex/claude-code.
- Fully retired the **phoenix** decompiler (angr driven with the Phoenix
  structurer). It was already hidden from the published site, so no published
  number moves; its harness (the `RawAngrPhoenixDecompiler` backend and the
  `structurer` override machinery), registry entry, and docs are removed.

### 2026-07-22

- **DecBench goes live** with support for 7 traditional decompilers, 2 LLMs (partial), and 3 defining metrics.
- An expanded evaluation of AI agents is planned after credits are secured for running those evaluations.
