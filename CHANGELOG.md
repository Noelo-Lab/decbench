# Changelog

Significant changes to DecBench that introduce or update results.

### 2026-07-23

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
