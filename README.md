# DecBench

<p align="center">
  <a href="https://decbench.com">
    <img src="./assets/decbench_smaller.png" alt="DecBench">
  </a>
</p>

Over the last 30 years, binary decompilers have made the steady march towards _perfect decompilation_: where decompilers recover the exact source code.
However, that _perfect_ has yet to be measured meaningfully, and is often defined across multiple axes. 

DecBench is an experimental benchmark to compare decompilers, and modern LLMs, at the task of recovering _exact_ source code.
This benchmark defines new metrics and datasets that represent the various directions of exactness for decompilers: structure, types, and precise recompilability. 
This benchmark is also _living_: as new decompiler/LLMs are released, their scores will be added to the leaderboard!
Community feedback is welcome!

See the live page for the latest results, insights, and purpose statement: [https://decbench.com](https://decbench.com)

## Metrics

DecBench evaluates decompilers using three core metrics:

| Metric | What it measures | How it works |
|--------|-----------------|--------------|
| **Structural Correctness (GED)** | Control flow recovery | Graph Edit Distance between source and decompiled CFGs using [cfgutils](https://github.com/angr/cfgutils) |
| **Type Correctness** | Variable type recovery | Compares decompiled variable types against DWARF debug info |
| **Recompilation Bytematch** | Recompilable, semantically-equivalent code | Recompiles each decompiled function with the **original toolchain** (matching its format/arch/opt flags) after a compilability **fixup** pass, then diffs the assembly via Jaccard similarity with linker-dependent operands normalized away |

A **Union** score tracks the percentage of functions where a decompiler achieves a perfect match on *one of three* metrics — i.e. the source was "perfect" by one direction.

## Quickstart
DecBench runs a four-stage pipeline:

```
Source Code (TOML config)
    --> Compile (gcc / cross / MinGW, multiple -O levels)
    --> Decompile (angr, Ghidra, IDA, Binary Ninja, ...)
    --> Evaluate (GED + Type Match + Byte Match)
    --> Scoreboard + HTML Report
```

You can access/reproduce all of them using our command-line utility and [public dataset](https://huggingface.co/datasets/noelo-lab/decbench-dataset).

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

The `compiled/` directories keep the preprocessed `.i` sources emitted at build
time (`-save-temps=obj`) alongside the binaries — they are **required**, not
build debris: GED's source-side CFGs are parsed exclusively from them, because
Joern needs macro-expanded, ifdef-resolved code to parse completely (raw `.c`
with unexpanded includes does not). Without the `.i` files, GED is silently
skipped for the entire run.

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

CI **never builds the site** — building needs every decompiler, a ~1.9 GB Joern,
and ~15 GB of compiled binaries. The maintainer builds locally and commits the
tree; [`.github/workflows/pages.yml`](.github/workflows/pages.yml) only uploads
what is already in `site/`.

```bash
decbench site build results/full_run -o site/      # 1. build locally
git add site && git commit -m 'site: refresh'      # 2. commit it (site/ is deliberately NOT gitignored)
git push                                           # 3. Actions deploys it
```

The workflow triggers on pushes to `main` that touch `site/**`, failing loudly if
`site/index.html` or `site/data/aggregates.json` is missing; the tree's data
contract is [`docs/SITE_DATA_SCHEMA.md`](docs/SITE_DATA_SCHEMA.md).

### Editing the site's text

**Every string a maintainer might want to reword lives in
`decbench/rendering/content/` — not in `html.py`.** Edit a file there, re-render,
done: no benchmark re-run, no Python.

| File | Holds |
|------|-------|
| `<view>.md` | each view's title and prose — `leaderboard.md`, `data.md`, `view.md`, `changelog.md`, `about.md` |
| `site.toml` | brand block, sidebar, footer, banners, side stats, and which decompilers are site-hidden / sample-set-only |
| `views.toml` | the view registry — which views exist, nav order + labels, which is `default`, which need function data |
| `metrics.toml` | per-metric display name, short column label, order, and the definition of *perfect* |
| `datasets.toml` | the 5 dataset presets' labels + descriptions, and which is `default` |
| `decompilers.toml` | the decompiler registry — official display names, project links, and version labels, rendered wherever the site names a decompiler |
| `categories.toml` | the software-type taxonomy on the About page's dataset tables |
| `pricing.toml` | per-model USD/MTok list prices for the Data page's cost table — applied at render time against the token facts in `FunctionData.cost_info` (gathered by `decbench/scoring/cost.py` via `scripts/compute_cost_info.py`), so a price fix needs only a re-render |

The `.md` conventions are documented in `leaderboard.md`'s header. A view's `id`
in `views.toml` must match its `<id>.md`. `datasets.toml` owns only preset
*presentation* — which functions are *in* a preset is scoring logic in
`decbench/scoring/datasets.py`.

## Finding improvement cases

You are a decompiler developer and you want to find ways to improve your decompiler based on these results?
Use the `improvement` command, which can help you find good starting cases. 

The example below uses **GED** (structural correctness — CFG graph edit distance, where **lower is better** and `0` is a perfect structural match):
```bash
# Where does angr (base) structurally beat ghidra (target)? -m ged is the default.
decbench improvements results/sailr_full -b angr -t ghidra -m ged
decbench improvements results/sailr_full -b angr -t ghidra -m ged --perfect-only
```

Each row locates the function on disk — binary, path to the compiled binary, and the function symbol + address — so you can jump straight to it:
```
angr beats ghidra on 'ged' — 356 case(s)  [base-perfect only]
metric: ged  (lower is better, perfect = 0)
showing 1 of 356, largest margin first

── libacl / O0 / getfacl ──  results/sailr_full/O0/libacl/compiled/getfacl
   0x281a  get_list   angr=0*  ghidra=38  Δ38
```

## Published datasets

Benchmark runs can be published as a public, reusable dataset (compiled
binaries, preprocessed sources, source/decompiled CFGs, per-function results and
scores) and pulled back down without recompiling or re-decompiling:

```bash
# Download a published config: sample-set / large / unoptimized / optimized /
# inlined / full.
decbench download sample-set --dest ./decbench-data
#   (thin alias for the standalone `decbench-data` consumer package; fetch a
#    subset with --include binaries,sources,cfgs,results,scores)

# Publish a results tree to the dataset repo layout.
python scripts/publish_dataset.py results/full_run --dest ~/github/decbench-dataset
```

See [docs/DATASET_PUBLISHING.md](docs/DATASET_PUBLISHING.md) for the repo layout,
the publisher, and the lightweight consumer CLI.