# DecBench Dataset Publishing — Build Contract

This document is the **single source of truth** for publishing the DecBench
benchmark data to the HuggingFace dataset repo and for the consumer CLI that
pulls it back down. It is the contract that three independently-built
components implement against; paths, schemas, and key conventions here are
normative — do not diverge from them.

- **Source data**: a completed results tree at `results/full_run` (the richest:
  6 decompilers — `angr`, `phoenix`, `ghidra`, `ida`, `binja`, `kuna`; 40
  projects; O0 / O2 / O2-noinline; ~806 evaluated binaries; 110,992 function
  records). Its `function_results.json` (schema v2) is the authoritative index
  of what was evaluated and is the anchor the publisher iterates over.
- **Dataset repo**: `~/github/decbench-dataset`, a HuggingFace *dataset* git repo
  with `repo_id = "noelo-lab/decbench-dataset"` (remote
  `git@hf.co:datasets/noelo-lab/decbench-dataset`). Large files go through Git
  LFS (`.gitattributes` already covers common binary/archive suffixes; the
  publisher must extend it for the file types it writes — see §6).

## 0. Terminology / keys

A function is identified by the 4-tuple **(project, opt, binary, function)**,
matching `decbench.scoring.aggregator` (`project::opt::binary::function`) and
`decbench.utils.results_tree`.

- `opt` ∈ `{"O0", "O2", "O2-noinline"}` (the three published optimization
  levels). NOTE: the user informally called the inlined variant "O2-inlined";
  in DecBench **plain `O2` is the one *with* inlining** and `O2-noinline`
  disables it. We keep the canonical `O2` / `O2-noinline` names on disk and
  document the mapping in the dataset card.
- `binary` is the **stem** as stored in `function_results.json` group records
  (e.g. `example`, `update-passwd`, `libz.so.1.2`) — NOT necessarily the
  on-disk filename, which may carry a suffix (`libz.so.1.2.13`, `mydoom.exe`).
  Resolve the real file with `decbench.utils.results_tree.resolve_binary`.
- Decompiler ids in `full_run` are single-version, so their unversioned `name`
  is used everywhere (`angr`, `phoenix`, `ghidra`, `ida`, `binja`, `kuna`). The
  on-disk decompiled artifact is `decompiled/<name>_<stem>.c` (+ `.toml`).

## 1. Published repo layout

```
decbench-dataset/
├── README.md                       # HF dataset card (YAML front-matter) + usage
├── dataset.toml                    # top-level index of configs + dataset metadata (§4)
├── configs/
│   ├── tiny/manifest.json          # per-config download manifest (§3)
│   ├── tiny/function_results.json  # scores filtered to this config's functions
│   ├── hard/manifest.json
│   ├── hard/function_results.json
│   ├── hard-inlined/manifest.json
│   ├── hard-inlined/function_results.json
│   └── full/manifest.json          # full: scores live at results/function_results.json
├── binaries/<opt>/<project>/<file>            # the compiled binary (real filename)
├── sources/<project>/<tu>.c                   # header-stripped project-only source, dedup by content
├── pipeline_data/
│   └── source_cfgs/<opt>/<project>/<stem>.json   # {function: node-link CFG} (§5)
├── results/
│   ├── function_results.json       # master per-function scores (all decompilers)
│   ├── scoreboard.toml             # aggregate leaderboard (copied verbatim)
│   └── <decompiler>/<opt>/<project>/<stem>.c   # decompiled C (+ sibling <stem>.toml)
└── decbench_data/                  # the lightweight consumer CLI (installable, §7)
    pyproject.toml                  # at repo root, installs `decbench-data` console script
```

`results/<decompiler>/` satisfies "results, which should have decompiler as each
folder." The cross-decompiler `function_results.json` / `scoreboard.toml` sit at
`results/` root (they aren't per-decompiler).

## 2. Publisher responsibilities (component 2 — lives in `decbench/`)

Implement as a package `decbench/publish/` with a thin CLI
`scripts/publish_dataset.py`. It reads `results/full_run` and writes into a
dataset-repo root (default `~/github/decbench-dataset`). It must be **idempotent
and resumable** (safe to re-run; skip work already done by content/size check).

Anchor: load `function_results.json` via
`decbench.models.function_data.FunctionData.from_json`, then
`decbench.scoring.datasets.assign_datasets(fd)` (idempotent; tags every record's
`.datasets` with the presets `full`/`hard`/`hard-inlined`/`tiny`). Iterate its
`groups` (each is one `(project, opt, binary-stem)`).

For each group:
1. **Binary** — `resolve_binary(compiled_dir(root,opt,project), stem)` → copy the
   real file to `binaries/<opt>/<project>/<filename>`. Record sha256 + size.
   Skip (don't fail) groups whose binary can't be resolved; log them.
2. **Decompiled results** — for each decompiler `d`, if
   `decompiled/<d>_<stem>.c` exists, copy it (and sibling `.toml`) to
   `results/<d>/<opt>/<project>/<stem>.c` (+ `.toml`).
3. **Source CFGs** — write `pipeline_data/source_cfgs/<opt>/<project>/<stem>.json`
   (§5). This is the compute-heavy step; gate it behind a `--cfgs` flag and make
   it independently resumable (skip if the output file already exists). The
   fast metadata/layout build must work WITHOUT `--cfgs`.

Per project (once): **Sources** — collect the project's `.i` files from all its
`compiled/` dirs across opt levels, run
`decbench.utils.cfg.strip_system_headers` on each, and write the stripped text
as `sources/<project>/<tu>.c` where `<tu>` is the `.i` basename with `.c`
suffix. **Deduplicate by stripped content** across opt levels (identical content
→ write once). Record the resulting file list per project.

Manifests / index: after the walk, build and write `dataset.toml` (§4) and
`configs/<name>/manifest.json` + filtered `function_results.json` for the three
non-full configs, plus `configs/full/manifest.json` (§3). Filtered scores use
`decbench.scoring.subset.filter_function_data`-style filtering (or reuse a
`SubsetManifest`) restricted to the functions tagged with that preset.

Also **extend `.gitattributes`** in the dataset repo so the binary artifacts are
tracked by LFS (§6), and never overwrite the HF-managed LFS lines already there.

### CLI surface (`scripts/publish_dataset.py`)
```
python scripts/publish_dataset.py <results_dir> [--dest ~/github/decbench-dataset]
    [--cfgs] [--cfg-workers N] [--configs tiny,hard,hard-inlined,full]
    [--only-config tiny] [--skip-binaries] [--skip-results] [--skip-sources]
```
Print a summary (counts + bytes written per section). A no-`--cfgs` run must
complete the whole layout except the CFG JSONs.

## 3. Config manifest schema — `configs/<name>/manifest.json`

Plain JSON (the consumer CLI parses it with stdlib `json`; the publisher may use
pydantic to write it). Every path is **repo-relative POSIX**. Self-contained: a
consumer can download exactly a config from this file alone.

```jsonc
{
  "config": "tiny",
  "description": "~100 functions evenly sampled across inlined/optimized/unoptimized/large and projects",
  "dataset_repo": "noelo-lab/decbench-dataset",
  "created": "2026-07-04T00:00:00",            // ISO; stamped by publisher (not inside a workflow)
  "decompilers": ["angr","phoenix","ghidra","ida","binja","kuna"],
  "metrics": ["byte_match","ged","type_match"],
  "function_count": 100,
  "binary_count": 100,
  "scores": "configs/tiny/function_results.json",  // full uses "results/function_results.json"
  "projects": {
    "zlib": { "sources": ["sources/zlib/deflate.c", "sources/zlib/inflate.c"] }
    // one entry per project that appears in this config; sources = stripped TUs for that project
  },
  "binaries": [
    {
      "project": "zlib",
      "opt": "O0",
      "binary": "example",                       // stem (join key into function_results.json)
      "binary_path": "binaries/O0/zlib/example", // real file (may differ from stem)
      "sha256": "…", "size": 12345,
      "source_cfg_path": "pipeline_data/source_cfgs/O0/zlib/example.json",
      "results": {                               // present decompiler outputs only
        "angr":   "results/angr/O0/zlib/example.c",
        "ghidra": "results/ghidra/O0/zlib/example.c"
      },
      "functions": ["test_compress","test_inflate"]  // functions THIS config selected from this binary
    }
  ]
}
```

`configs/full/manifest.json` has the same shape but lists **all** binaries and
sets `"scores": "results/function_results.json"`; its per-binary `functions` may
be omitted or list all functions (full = everything). `source_cfg_path` /
`results` entries are included only when the corresponding file was written
(e.g. CFGs only after a `--cfgs` run) so the CLI never asks the hub for a missing
file — the publisher must reconcile the manifest with what is actually on disk.

## 4. Top-level index — `dataset.toml`

```toml
[dataset]
name = "decbench-dataset"
repo_id = "noelo-lab/decbench-dataset"
opt_levels = ["O0", "O2", "O2-noinline"]
decompilers = ["angr","phoenix","ghidra","ida","binja","kuna"]
metrics = ["byte_match","ged","type_match"]
projects = 40
binaries = 806
functions = 110992

[configs.tiny]
description = "~100 functions evenly sampled across categories and projects"
function_count = 100
binary_count   = 100
manifest = "configs/tiny/manifest.json"
scores   = "configs/tiny/function_results.json"

[configs.hard]        # optimized (O2-noinline), large functions only
...
[configs."hard-inlined"]   # optimized WITH inlining (O2), large functions only
...
[configs.full]        # everything
manifest = "configs/full/manifest.json"
scores   = "results/function_results.json"
```

Counts come from the actual walk (do not hardcode). Config descriptions mirror
`decbench.scoring.datasets.PRESETS`.

## 5. Source-CFG serialization — `pipeline_data/source_cfgs/<opt>/<project>/<stem>.json`

**GED is purely structural** — `cfgutils.similarity.vj_ged` (the metric's engine)
compares only graph topology (per-node parent/child counts via a positional
`GraphCache`); it never reads node labels or attributes. Therefore a topological
serialization reproduces the exact GED value. Store, per binary, the
`function → CFG` map the pipeline used:

```jsonc
{
  "opt": "O0", "project": "zlib", "binary": "example",
  "generator": "pyjoern",                 // provenance
  "functions": {
    "test_compress": {
      "nodes": [0, 1, 2],                  // ints 0..n-1
      "edges": [[0,1],[1,2]],
      "labels": {"0": "<Block: None.0, 4 statements>"}   // optional, human-readable; not used by GED
    }
  }
}
```

Build it by reusing `decbench.utils.cfg.extract_cfgs_from_source` on the binary's
project `.i` files and merging (last-writer-wins on name collisions, exactly like
`pipeline/evaluate.py` builds `all_source_cfgs`). Relabel each DiGraph's nodes to
`0..n-1` (stable order) and emit `nodes`/`edges`. **Deduplicate Joern runs by
stripped-content hash** — cache `stripped_sha -> {func: (nodes,edges,labels)}` so
each unique translation unit is parsed once (Joern spawns a JVM per parse, so
this is the dominant cost). Resumable: skip a `<stem>.json` that already exists.

A round-trip check (rebuild `nx.DiGraph` from `nodes`/`edges`, run `vj_ged`
against a decompiled CFG, compare to the stored score in `function_results.json`)
should match for spot-checked functions.

## 6. `.gitattributes` (LFS)

The published binaries have no extension, so add rules so Git LFS tracks them
without disturbing the HF defaults already present. Append (idempotently):
```
binaries/** filter=lfs diff=lfs merge=lfs -text
results/**/*.c -filter -diff -merge text    # keep decompiled C as normal text
```
Binaries under `binaries/**` are arbitrary ELF/PE → LFS. Text artifacts
(`sources/**/*.c`, `results/**`, `pipeline_data/**/*.json`, `configs/**`,
`dataset.toml`) stay as normal git text so they diff nicely. Do NOT LFS-track the
JSON/TOML/C text. (If any single JSON is very large — e.g. the master
`results/function_results.json` at ~165 MB — LFS-track that one file explicitly:
`results/function_results.json filter=lfs diff=lfs merge=lfs -text`.)

## 7. Consumer CLI (component 3 — lives in the dataset repo)

A **lightweight, self-contained** package `decbench_data/` in
`~/github/decbench-dataset` with a root `pyproject.toml`. Minimal deps only:
`huggingface_hub`, `click` (or argparse to avoid even that), and stdlib `tomllib`
(3.11+) / `tomli` fallback. It MUST NOT import `decbench` or any heavy RE deps.

Console script `decbench-data` (and `python -m decbench_data`). Commands:

- `decbench-data list` — list configs from `dataset.toml` (name, description,
  function/binary counts).
- `decbench-data info <config>` — show what a config contains (projects,
  binaries, functions, per-metric perfect rates if cheap to derive from the
  filtered scores) without downloading the heavy artifacts.
- `decbench-data download <config> [--dest DIR] [--include ...] [--exclude ...]
  [--repo-path PATH] [--revision REV] [--workers N]` — resolve the config's
  `manifest.json`, then fetch every listed file (binaries, sources, source CFGs,
  decompiled results, scores) and lay them out under `DEST` **mirroring the repo
  layout** (so the result is directly analyzable and matches paths in the
  manifest). `--include`/`--exclude` select sections
  (`binaries,sources,cfgs,results,scores`); default = all.

Download mechanism: `huggingface_hub.hf_hub_download(repo_id=..., repo_type=
"dataset", filename=<repo-relative path>, revision=..., local_dir=DEST)` per file
so only the config's subset is transferred (never the whole repo). Verify sha256
for binaries when present in the manifest. Show progress; be resumable (skip
files already present with matching size/sha).

**Local fallback for offline/testing**: if `--repo-path PATH` is given (or env
`DECBENCH_DATASET_LOCAL`), read `dataset.toml` / manifests / files from that
local directory by copying instead of hitting the hub. This lets the CLI be
verified against a freshly-populated repo before anything is pushed to HF.

A tiny quickstart in the CLI package (`decbench_data/README.md` or docstring):
```
pip install decbench-data           # or: pip install git+https://huggingface.co/datasets/noelo-lab/decbench-dataset
decbench-data list
decbench-data download tiny --dest ./decbench-tiny
```

## 8. `decbench download` alias (component 4 — lives in `decbench/cli.py`)

Add a thin top-level `download` command to the main decbench CLI so existing
users get `decbench download tiny`. It should NOT duplicate logic: prefer to
import and call the `decbench_data` package if importable; otherwise print a
one-line install hint (`pip install decbench-data`). Keep the heavy decbench
imports lazy so `decbench download` works even in a minimal environment.

## 9. Acceptance (component 5 — integration, done by the orchestrator)

1. `python scripts/publish_dataset.py results/full_run --dest ~/github/decbench-dataset`
   (no `--cfgs`) populates binaries/sources/results/configs/dataset.toml.
2. Source-CFG generation runs (resumable) at least for the `tiny` config's
   binaries; ideally all.
3. `DECBENCH_DATASET_LOCAL=~/github/decbench-dataset decbench-data download tiny
   --dest /tmp/decbench-tiny` lays out ~100 binaries + sources + cfgs + scores,
   all files present, sha256 verified.
4. `decbench-data list` / `info tiny` print correct counts.
5. `decbench download tiny` (main CLI) reaches the same code path.
6. Nothing is pushed to HF automatically — leave `git add/commit/push` to the user.
```
