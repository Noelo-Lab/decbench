# DecBench

A benchmarking suite for evaluating decompiler performance across three dimensions of correctness.

## Metrics

DecBench evaluates decompilers using three core metrics:

| Metric | What it measures | How it works |
|--------|-----------------|--------------|
| **Structural Correctness (GED)** | Control flow recovery | Graph Edit Distance between source and decompiled CFGs using [cfgutils](https://github.com/angr/cfgutils) |
| **Type Correctness** | Variable type recovery | Compares decompiled variable types against DWARF debug info ground truth |
| **Recompilation Bytematch** | Recompilable, semantically-equivalent code | Recompiles each decompiled function with the **original toolchain** (matching its format/arch/opt flags) after a compilability **fixup** pass, then diffs the assembly via Jaccard similarity with linker-dependent operands normalized away |

An **Overall** score tracks the percentage of functions where a decompiler achieves a perfect match on *all three* metrics simultaneously — i.e. the source was precisely recovered.

### Byte-match fairness (fixup + normalization)

Raw decompiler output rarely recompiles as-is (Ghidra emits pseudo-types like
`undefined4`/`code`; angr emits illegal `GLIBC_2.2.5::stderr` tokens), so naive
recompilation scores almost everything 0. To measure *logic* recovery fairly,
the byte-match metric applies the same two passes to every decompiler:

- **Compilability fixup** (`decbench/metrics/fixup.py`) — a deterministic,
  algorithmic (no LLM) gcc-diagnostic-driven self-repair loop: it strips illegal
  tokens, then injects *only* what the compiler reports missing (typedefs for
  pseudo-types, stubs for undeclared symbols), never redefining what the
  decompiler already declared. Raised the compile rate from ~16–39% to ~44–46%.
- **Operand normalization** — branch/call targets and PC-relative (`[rip±x]`,
  AArch64 `adrp`) displacements are link-time-dependent, so they're blanked
  before diffing; otherwise an unlinked `call` displacement counts as a mismatch.

Type recovery is scored separately (Type Correctness), so fixing types just to
compile does not inflate this metric. Each function also records whether it
recompiled at all, surfaced as the report's per-decompiler **compile rate**.

## Pipeline

DecBench runs a three-stage pipeline:

```
Source Code (TOML config)
    --> Compile (gcc / cross / MinGW, multiple -O levels)
    --> Decompile (angr, phoenix, Ghidra, IDA, Binary Ninja, ...)
    --> Evaluate (GED + Type Match + Byte Match)
    --> Scoreboard + HTML Report
```

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run full pipeline on a project
decbench run projects/sailr/coreutils.toml

# Run with specific decompilers and metrics
decbench run project.toml -d angr -d ghidra -m ged -m type_match -m byte_match

# Evaluate a single binary
decbench evaluate binary.elf -s source.c

# Generate HTML report from results
decbench report results/scoreboard.toml -o report.html

# List available decompilers and metrics
decbench list-decompilers
decbench list-metrics
```

## Generating results

`decbench run` works for a single project, but real benchmark runs use the
resilient drivers in `scripts/` — they checkpoint per project (so a multi-hour
run survives crashes) and use the `spawn` multiprocessing context (the default
`fork` deadlocks workers once angr's threads are live).

```bash
# 1. Compile every project at every opt level into a results tree.
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  python scripts/compile_all.py results/sailr_full 16        # 16 workers

# 2. Decompile + evaluate + write the scoreboard, function data, and report.
DECBENCH_WORKERS=40 DECBENCH_DECOMPILERS=angr,ghidra \
  GHIDRA_INSTALL_DIR=/path/to/ghidra \
  python scripts/run_benchmark.py results/sailr_full
#   Restart resumes from per-project checkpoints.
#   `... results/sailr_full -- grep` limits to named projects.
```

This produces, under `results/sailr_full/`:

- `scoreboard.toml` — machine-readable per-metric + overall scores
- `function_results.json` — the per-function dataset the HTML report embeds
  (values, perfect flags, dataset tags, side-by-side **samples** with source,
  **hardest** functions, per-decompiler **compile rates**)
- `<opt>/<project>/{compiled,decompiled,evaluated}/` — intermediate artifacts

### Re-scoring byte-match without re-decompiling

Decompilation is the slow part. To re-score **only** byte-match over an existing
results tree (e.g. after a metric change) — reusing the stored `decompiled/*.c`
and `compiled/` binaries — run the two offline scripts, then re-render:

```bash
python scripts/reeval_bytematch.py results/sailr_full 40      # -> byte_match_new.json (parallel, resumable)
python scripts/rebuild_function_data.py results/sailr_full    # -> refreshed function_results.json + scoreboard.toml
decbench report results/sailr_full/scoreboard.toml -o results/sailr_full/report.html
```

## Rendering the site

Two commands render the **same page** from the same skeleton and the same
content; they differ only in how it is delivered.

| Command | Output | Use it when |
|---------|--------|-------------|
| `decbench report` | one self-contained `.html` (~7.1 MB) | you want a single file to open locally, email, or archive — CSS, JS, font and all data are inlined, so it works over `file://` |
| `decbench site build` | a split tree in `site/` (~7.0 MB) | you are publishing to GitHub Pages — assets and data are separate files the browser caches, and only ~0.10 MB loads before first paint |

```bash
# Single self-contained file. Takes a SCOREBOARD path; if a sibling
# function_results.json exists, the report is fully interactive.
decbench report results/full_run/scoreboard.toml -o results/full_run/report.html

# Deployable Pages tree. Takes a RESULTS TREE, and requires its
# function_results.json — every view is computed from per-function data.
decbench site build results/full_run -o site/
```

### Publishing to GitHub Pages

CI **never builds the site.** Building it needs every decompiler, a ~1.9 GB
Joern, and ~15 GB of compiled binaries — none of which can live in Actions. The
maintainer builds locally and commits the tree;
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) only uploads what is
already in `site/`.

```bash
decbench site build results/full_run -o site/      # 1. build locally
git add site && git commit -m 'site: refresh'      # 2. commit it (site/ is deliberately NOT gitignored)
git push                                           # 3. Actions deploys it
```

The workflow triggers on pushes to `main` that touch `site/**`, and fails loudly
if `site/index.html` or `site/data/aggregates.json` is missing. The data contract
for the tree is [`docs/SITE_DATA_SCHEMA.md`](docs/SITE_DATA_SCHEMA.md).

### Views

The report is a **single-page app** (no server, no external assets — the web font
is vendored) themed in a terminal aesthetic. A left **sidebar** switches views and
holds a **dataset selector** (`full` / `hard` / `hard-inlined` / `unoptimized` /
`tiny`) plus a normalize-failures toggle. Every aggregate for those selectors is
precomputed at build time, so switching is a lookup rather than a client-side
recompute.

| View | What it shows |
|------|---------------|
| **Leaderboard** | swebench-style ranked table — one row per decompiler, columns for Overall + each metric's perfect % + compile rate; sortable by any column. The page the site opens on |
| **Metrics** | the three decompilation goals, the metric for each, and per-decompiler perfect/compile rates |
| **Distance** | raw edit distance to a perfect result per metric (lower is better) — mean, median, and how many functions are already at 0; a finer signal than the leaderboard's perfect rate |
| **Dataset** | the corpus — software types, every project's size, and how much of GED is lost to our own tooling (Joern source-parse failures) rather than to the decompilers |
| **Compare** | original source side-by-side with each decompiler's output for a curated set of functions, with per-metric scores |
| **Hardest** | the worst-scoring functions, with decompiled code and source |
| **Historical** | per-metric perfect % across decompiler versions (e.g. `ghidra@12.0` vs `ghidra@12.1`) |
| **About** | what the benchmark is and how to read it |

### Editing the site's text

**Every string a maintainer might want to reword lives in
`decbench/rendering/content/` — not in `html.py`.** Edit a file there, re-render,
done: no benchmark re-run, no Python.

| File | Holds |
|------|-------|
| `<view>.md` | each view's title and prose — `leaderboard.md`, `metrics.md`, `distance.md`, `dataset.md`, `compare.md`, `hardest.md`, `history.md`, `about.md` |
| `site.toml` | brand block, sidebar, footer, banners, side stats |
| `views.toml` | the view registry — which views exist, nav order + labels, which is `default`, which need function data |
| `metrics.toml` | per-metric display name, short column label, order, and the definition of *perfect* |
| `datasets.toml` | the 5 dataset presets' labels + descriptions, and which is `default` |
| `categories.toml` | the software-type taxonomy on the Dataset page |

The `.md` conventions are documented in `leaderboard.md`'s header. A view's `id`
in `views.toml` must match its `<id>.md`. `datasets.toml` owns only preset
*presentation* — which functions are *in* a preset is scoring logic in
`decbench/scoring/datasets.py`.

## Finding improvement cases

`decbench improvements` mines a results tree for the concrete functions where one
decompiler beats another on a metric — a targeted to-do list for whoever is
improving the losing decompiler. It reads the `function_results.json` produced by
a run and, per function, compares a **base** decompiler (the winner) against a
**target** (the one to improve), respecting the metric's direction.

The example below uses **GED** (structural correctness — CFG graph edit distance,
where **lower is better** and `0` is a perfect structural match):

```bash
# Where does angr (base) structurally beat ghidra (target)? -m ged is the default.
decbench improvements results/sailr_full -b angr -t ghidra -m ged

# Strongest signal only: functions angr recovers *perfectly* (GED == 0) while
# ghidra does not — the clearest wins to learn from.
decbench improvements results/sailr_full -b angr -t ghidra -m ged --perfect-only
```

Each row locates the function on disk — binary, path to the compiled binary, and
the function symbol + address — so you can jump straight to it:

```
angr beats ghidra on 'ged' — 356 case(s)  [base-perfect only]
metric: ged  (lower is better, perfect = 0)
showing 3 of 356, largest margin first

── libacl / O0 / getfacl ──  results/sailr_full/O0/libacl/compiled/getfacl
   0x281a  get_list   angr=0*  ghidra=38  Δ38
── coreutils / O2-noinline / shred ──  results/sailr_full/O2-noinline/coreutils/compiled/shred
   0x4160  do_wipefd  angr=0*  ghidra=36  Δ36
```

`Δ` is how much better the base scored (here, ghidra's GED); `*` marks a perfect
base score. Cases are ordered by the largest base advantage first.

| Flag | Meaning |
|------|---------|
| `-b, --base-decompiler` | the decompiler that is **winning** (required) |
| `-t, --target-decompiler` | the decompiler that is **losing** — the one to improve (required) |
| `-m, --metric` | metric to compare on: `ged` (default), `type_match`, or `byte_match`. Direction is applied automatically — GED is lower-is-better/perfect `0`; type_match and byte_match are higher-is-better/perfect `1` |
| `--perfect-only` | only functions where the base is a **perfect** match on the metric (GED `0`, type/byte_match `1`) |
| `--include-target-missing` | also include functions the base scored but the target has no usable score for (failed to decompile, or the metric errored) |
| `--limit N` | cap the cases shown (`0` = all; default 50) |
| `-f, --format text\|json` | `json` emits one object per case (binary path, address, values, margin, labels) for scripting |

`RESULTS` may be a results directory or a `function_results.json` file directly.

## Published datasets

Benchmark runs can be published as a public, reusable dataset (compiled
binaries, preprocessed sources, source/decompiled CFGs, per-function results and
scores) and pulled back down without recompiling or re-decompiling:

```bash
# Download a published config: full / hard / hard-inlined / tiny.
decbench download tiny --dest ./decbench-data
#   (thin alias for the standalone `decbench-data` consumer package; fetch a
#    subset with --include binaries,sources,cfgs,results,scores)

# Publish a results tree to the dataset repo layout.
python scripts/publish_dataset.py results/full_run --dest ~/github/decbench-dataset
```

See [docs/DATASET_PUBLISHING.md](docs/DATASET_PUBLISHING.md) for the repo layout,
the publisher, and the lightweight consumer CLI.

## Project Configuration

Projects are defined via TOML files:

```toml
name = "coreutils"
version = "9.4"
source_remote = "https://ftp.gnu.org/gnu/coreutils/coreutils-9.4.tar.xz"
remote_type = "tar"
source_dir = "src"
make_cmd = "make"
pre_make_cmds = ["./configure --quiet"]

[compilation]
optimization_levels = ["O0", "O2"]
base_flags = ["-g", "-fno-inline", "-fno-builtin"]
```

## Supported Decompilers

Each backend subclasses the `Decompiler` ABC and registers by name; a
decompiler's identity is `name` or `name@version` (e.g. `ghidra@12.0` vs
`ghidra@12.1`), so multiple versions can be benchmarked as distinct columns.
`decbench list-decompilers` shows what's available on the current machine.

- **angr** - Open-source binary analysis framework (default SAILR structurer)
- **phoenix** - angr driven with the Phoenix structurer (a distinct decompiler)
- **Ghidra** - NSA's open-source reverse engineering tool (via pyghidra)
- **IDA Pro** - Commercial decompiler (via idalib, IDA 9+)
- **Binary Ninja** - Commercial decompiler (headless, needs a license)
- **kuna** - experimental structuring backend

The canonical `angr`/`ghidra`/`ida`/`binja` backends drive each tool's own API
directly (no `declib`). Additional backends run in Docker: **RetDec**, **Reko**,
and **r2dec** (build images with `decbench decompiler-build <name>`).

## Results

After running the pipeline, DecBench generates:

- **Scoreboard** (`scoreboard.toml`) — machine-readable per-metric + overall scores
- **Function data** (`function_results.json`) — per-function dataset embedded by the report
- **HTML Report** — the interactive single-page site described in [Rendering the site](#rendering-the-site)
- **Per-binary TOML files** — detailed per-function metric values

`decbench run` also prints a text scoreboard to the terminal, e.g.:
```
============================================================
  DecBench Scoreboard
  Functions: 2,309 | Binaries: 2
============================================================

GED:
  > angr                       48.8%

BYTE_MATCH:
  > angr                        1.7%

TYPE_MATCH:
  > angr                        0.0%

OVERALL (perfect on all metrics):
  > angr                        0.0%
============================================================
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Linting and formatting
ruff check .
black .
mypy decbench
```

## Architecture

```
decbench/
  pipeline/         # compile -> decompile -> evaluate orchestration
  metrics/          # ged.py, type_match.py, byte_match.py, fixup.py
  decompilers/      # angr, ghidra, ida plugins
  compilers/        # gcc plugin
  models/           # Pydantic data models
  scoring/          # aggregation, scoreboard, datasets, report extras
  rendering/        # the report + the deployable site
    html.py         #   skeleton assembly only — no CSS, no JS, no prose
    aggregate.py    #   build-time aggregation -> the site's JSON payloads
    site.py         #   the split GitHub Pages tree (decbench site build)
    content.py      #   loader for content/
    content/        #   ALL editable text: *.md per view + site/views/metrics/
                    #   datasets/categories .toml
    assets/         #   app.css, app.js, vendored font
  utils/            # binfmt.py, source_extract.py, cfg.py
  cli.py            # Click-based CLI
scripts/            # scalable run drivers + offline byte-match re-eval/rebuild
site/               # the built Pages tree, committed (see "Rendering the site")
docs/               # SITE_DATA_SCHEMA.md — the site's data contract
```

## Dependencies

- Python 3.10+
- [angr](https://angr.io/) - Binary analysis and decompilation
- [pyjoern](https://github.com/angr/pyjoern) - Source CFG extraction
- [cfgutils](https://github.com/angr/cfgutils) - Graph Edit Distance
- [pyelftools](https://github.com/eliben/pyelftools) - ELF/DWARF parsing
- [capstone](https://www.capstone-engine.org/) - Disassembly for byte matching
- [diff-match-patch](https://github.com/google/diff-match-patch) - Assembly diffing

## License

MIT
