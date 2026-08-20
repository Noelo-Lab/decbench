# AGENTS

Guidance for coding agents (Claude Code, Codex, …) working in this repository.
This file holds only the **mandatory** knowledge. Everything else lives
in `docs/` — read the matching doc before working in an area.

## Project Overview

DecBench is a benchmarking suite for evaluating decompiler performance. It
implements a three-stage pipeline (compile → decompile → evaluate) with
pluggable decompilers and three core metrics, and publishes the results as a
static site (https://decbench.com). The associated data produced from this
benchmark can be found at https://huggingface.co/datasets/noelo-lab/decbench-dataset.

## Docs index

| Doc | Read it before |
| --- | --- |
| `docs/benchmarking.md` | running anything at scale — this machine's decompiler installs + versions, the corpus (sailr/cps/malware), the run drivers + env knobs, and the overlay → finalize flow behind the published numbers |
| `docs/metrics.md` | touching a metric — GED / type_match / byte_match internals, fairness passes, metric caching |
| `docs/decompilers.md` | adding or debugging a backend — the plugin contract, the LLM/coding-agent backends, external submissions (the eval kit) |
| `docs/site.md` | touching the report or site — rendering architecture, the content system, build/deploy, the data schema |
| `docs/dataset-publishing.md` | publishing to / consuming the HuggingFace dataset repo |

## Environment

- Use the `decbench` virtualenv at `/home/mahaloz/.virtualenvs/decbench`
  (Python 3.14; decbench installed editable). Activate with
  `source /home/mahaloz/.virtualenvs/decbench/bin/activate`.
- Benchmark backends working on this machine: angr, ghidra (12.1/12.0 + three
  historical versions), ida (9.2 idalib), binja (5.3), kuna, r2dec, dewolf,
  and the codex/claude-code LLM agents. retdec/reko need their Docker images
  built first, and kimi-code needs a Kimi OAuth login.
  `decbench list-decompilers` shows live availability; install paths,
  licenses, and per-version config are in `docs/benchmarking.md`.
- Docker works here (no sudo needed).

## Common Commands

```bash
pip install -e ".[dev]"             # install for development
pytest                              # all tests, with coverage (real-decompiler tests auto-skip)
ruff check .                        # lint
black .                             # format
mypy decbench                       # type check

decbench run project.toml -O O0 -O O2 -d angr -d ghidra   # full pipeline, one project
decbench list-decompilers           # show available decompilers
decbench list-metrics               # show available metrics
decbench report scoreboard.toml     # render the HTML report
decbench site build results/full_run -o site/   # build the deployable Pages tree
```

Real benchmark runs use `scripts/compile_all.py` + `scripts/run_benchmark.py`
(checkpointed, resumable, spawn-based) — NOT a bare `decbench run`. A "full
run" always means every project in `projects/{sailr,cps,malware}/` × every
supported decompiler. Drivers, env knobs, and the full-run recipe:
`docs/benchmarking.md`.

## Architecture

```
decbench/
  pipeline/         # compile -> decompile -> evaluate (executor.py / PipelineExecutor)
  metrics/          # ged.py, type_match.py, byte_match.py, fixup.py
  decompilers/      # raw angr/ghidra/ida/binja + dewolf, dockerized, LLM agents
  compilers/        # gcc plugin
  models/           # Pydantic data models (project.py, function_data.py, ...)
  scoring/          # aggregation, scoreboard, dataset presets, report extras
  rendering/        # the report + the deployable site (see docs/site.md)
    content/        #   ALL editable prose/config; html.py is skeleton-only
  utils/            # binfmt.py, cfg.py, source_extract.py
  cli.py            # Click-based CLI entry point
scripts/            # scalable run drivers + offline metric re-eval/rebuild
projects/           # benchmark corpus TOMLs: sailr/ cps/ malware/
site/               # the built Pages tree (committed; CI only deploys it)
docs/               # the detailed reference docs (index above)
```

Data flow: project TOML → compile (binaries + preprocessed `.i` files) →
decompile (`DecompilationResult` per binary) → metrics (`MetricResult`) →
aggregate → `scoreboard.toml` + `function_results.json` → report / site.

Key conventions:

- **Decompiler identity is `name` or `name@version`** (e.g. `ghidra@12.1`);
  each versioned spec is its own comparable column everywhere downstream.
- **Addresses are stored in ELF-file-space** so they line up with DWARF.
- **Optimization levels map to GCC flags via `opt_gcc_flags()`**
  (`decbench/models/project.py`) — never `f"-{opt}"`. `O2-noinline` =
  `-O2 -fno-inline`; plain `O2` is a genuine O2 (inlining enabled).

## Critical rules (violating these silently corrupts results)

- **The published metric numbers are the reeval OVERLAYS**, not the checkpoint
  inline values. `function_results.json` is only ever written through
  `decbench/results_store.py`; the canonical rebuild is
  `scripts/finalize_results.py <tree>` (coverage-guarded; `--audit` scans for
  silent gaps). After adding a decompiler, refresh the overlays and
  re-finalize before publishing. Full flow: `docs/benchmarking.md`.
- **Multiprocessing must use `spawn`/`forkserver`, never `fork`** — forking
  workers after angr's threads start deadlocks them. All `scripts/` drivers
  set `spawn`; any new parallel driver must too.
- **If you change a metric's algorithm, bump its `cache_version`** class
  attr — the content-addressed cache otherwise serves stale values
  (`DECBENCH_NO_CACHE=1` bypasses; root: `DECBENCH_CACHE_DIR`).
- **Multi-version Ghidra needs one process per install** (pyghidra binds one
  JVM per process); the run drivers already isolate per task.
- **Malware targets are compile-only, container-only, NEVER executed** — the
  `is_malware` guard refuses bare-host builds; binaries never leave
  `results/`. See `projects/malware/README.md`.
- **The site's prose/CSS/JS is NOT in `html.py`** (skeleton assembly only) —
  edit `decbench/rendering/content/` + `assets/` and re-render; content edits
  never need a benchmark re-run. See `docs/site.md`.
- **Canonical decompiler names are the raw (declib-free) backends**; the
  declib ones are `*-declib`. Drivers must `import decbench.decompilers` (the
  whole package) so every backend registers.
- **When pushing to the website**, first verify that nothing extreme has changed. 
  An example is a decompiler in the new site have 50% less functions decompiled 
  than in the last update, or drastically changing rank. This can happen, but
  should only occur when MAJOR changes to the benchmark occur, like adding a 
  new metric or deleting many projects from the dataset.
- **When pushing to the website, also verify the View page still has content.**
  The leaderboard can look perfect while the View page silently loses every
  source sample, because the numbers and the sample bodies come from different
  places. Compare `site/data/samples.json` against the currently-published one
  before pushing: the difficulty mix (`easy`/`medium`/`hard`/`sample-set`) and
  the count of entries carrying a non-empty `source_code` must not drop.
  `source_status` names the miss reason on any entry that lost its source.
  The usual cause is running `scripts/finalize_results.py` (which rebuilds the
  `easy`/`medium`/`hard` tiers) from the wrong directory: checkpoints store
  binary paths RELATIVE to the repo root, so the run's cwd must be the checkout
  that actually holds `results/` — a git worktree does not (`results*` is
  gitignored), and every sample then fails with `binary_not_found`. Run the
  finalize/info-writer scripts from the main checkout and select a different
  code version with `PYTHONPATH=`, never by changing cwd.
- **When updating results** be sure to keep the huggingface-side dataset up to
  date with our changes, found at https://huggingface.co/datasets/noelo-lab/decbench-dataset.
  You can usually find a local clone one directory above this repo in
  `decbench-dataset`, which has results stored in it.
- Any time any public thing is created fully automatically, it should start with `[AUTOMATED]`. That goes for PRs, Issues (opening and responses). It should also be in the commit message, but can go outside of the tagline and more inside the extended part.

## Coding Standards

- Type hints required on all functions
- pytest for testing (fixtures in `tests/conftest.py`);
  `tests/example_project/` is the example C project — its Makefile uses
  `CFLAGS ?=` so the pipeline's env CFLAGS (which carry the opt level) take
  effect
- PEP 8 with 100 character lines
- One pull request per feature
- Autonomous updates to CHANGELOG.md is illegal. You can make a suggestion in the PR description, but these should be edited by human maintainers.
- After making changes to code, we should verify that the docs remain up-to-date with those changes.
- We want to minimize the inline comments we do in our code. Only in the rarest cases where code is especially confusing or a hack should we have inline comments. Comments in the headers of files is ok. Comments in the function prototype is also ok, but should be minimal. 

