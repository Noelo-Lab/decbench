# DecBench Dataset Publishing — Build Contract

This document is the **single source of truth** for publishing the DecBench
benchmark data to the HuggingFace dataset repo and for the consumer CLI that
pulls it back down. It is the contract the publisher (`decbench/publish/`, §2),
the consumer CLI (`decbench_data`, §7), and the `decbench download` alias (§8)
implement against; paths, schemas, and key conventions here are normative — do
not diverge from them.

- **Source data**: a completed results tree at `results/full_run` (the richest:
  9 decompilers — `angr`, `ghidra`, `ida`, `binja`, `kuna`,
  `r2dec`, `dewolf`, plus the sample-set-only LLM agents `codex` and
  `claude-code`; 40 projects; O0 / O2 / O2-noinline; ~806 evaluated binaries;
  ~95k function records — all counts flow from the tree at publish time, not
  from this doc). Its `function_results.json` (schema v2) is the authoritative
  index of what was evaluated and is the anchor the publisher iterates over.
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
  levels). In DecBench **plain `O2` is the one *with* inlining** and
  `O2-noinline` disables it; the canonical `O2` / `O2-noinline` names are kept
  on disk and the mapping is documented in the dataset card.
- `binary` is the **stem** as stored in `function_results.json` group records
  (e.g. `example`, `update-passwd`, `libz.so.1.2`) — NOT necessarily the
  on-disk filename, which may carry a suffix (`libz.so.1.2.13`, `mydoom.exe`).
  Resolve the real file with `decbench.utils.results_tree.resolve_binary`.
- Decompiler ids in `full_run` are single-version, so their unversioned `name`
  is used everywhere. The set is read from `function_results.json`, never
  hardcoded (currently the 9 above; `codex`/`claude-code` cover only the
  sample-set slice). The
  on-disk decompiled artifact is `decompiled/<name>_<stem>.c` (+ `.toml`).

## 1. Published repo layout

```
decbench-dataset/
├── README.md                       # HF dataset card (YAML front-matter) + usage
├── dataset.toml                    # top-level index of configs + dataset metadata (§4)
├── configs/
│   ├── sample-set/manifest.json          # per-config download manifest (§3)
│   ├── sample-set/function_results.json  # scores filtered to this config's functions
│   ├── large/manifest.json               # …same pair for large, unoptimized,
│   ├── large/function_results.json       #  optimized, and inlined
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

`results/<decompiler>/` keeps one folder per decompiler. The cross-decompiler
`function_results.json` / `scoreboard.toml` sit at `results/` root (they aren't
per-decompiler).

## 2. The publisher (`decbench/publish/`)

The publisher is the package `decbench/publish/` (`layout.py` + `cfg_export.py`)
driven by the thin CLI `scripts/publish_dataset.py`. It reads `results/full_run`
and writes into a dataset-repo root (default `~/github/decbench-dataset`). It is
**idempotent and resumable** (safe to re-run; already-done work is skipped by a
content/size check).

**Decompiler exclusions.** `layout.load_dataset` strips every trace of the
decompilers in `layout.EXCLUDED_DECOMPILERS` (currently empty) from the
loaded `FunctionData` before anything is copied or written —
`fd.decompilers`/`decompiler_versions`, per-function
`values`/`perfects`/`distances`/`decompiled`/`compiles`, `compile_rates`,
`samples`, `hardest`, and `history` (see `layout.strip_decompilers`). The
master `results/function_results.json` is therefore written from the stripped
in-memory object (never a verbatim file copy) and `results/scoreboard.toml` is
regenerated from it, so an excluded decompiler appears **nowhere** in the
published repo: no `results/<dec>/` folder, no manifest entry, no score column.
`scripts/publish_dataset.py --exclude-decompiler NAME` (repeatable) overrides
the set; `--no-exclusions` disables stripping entirely.

Anchor: it loads `function_results.json` via
`decbench.models.function_data.FunctionData.from_json`, then
`decbench.scoring.datasets.assign_datasets(fd)` (idempotent; tags every record's
`.datasets` with the five scoring presets `unoptimized` / `optimized` /
`inlined` / `large` / `sample-set` — `full` is a publisher-only
everything-config, not a preset). It iterates the `groups` (each is one
`(project, opt, binary-stem)`).

For each group it writes:
1. **Binary** — `resolve_binary(compiled_dir(root,opt,project), stem)` → the
   real file at `binaries/<opt>/<project>/<filename>`, recording sha256 + size.
   Groups whose binary can't be resolved are skipped and logged, not fatal.
2. **Decompiled results** — each existing `decompiled/<d>_<stem>.c` (and sibling
   `.toml`) → `results/<d>/<opt>/<project>/<stem>.c` (+ `.toml`).
3. **Source CFGs** — `pipeline_data/source_cfgs/<opt>/<project>/<stem>.json`
   (§5). This is the compute-heavy step, gated behind `--cfgs` and independently
   resumable (existing outputs are skipped); the fast metadata/layout build
   works WITHOUT `--cfgs`.

Per project (once): **Sources** — the project's `.i` files from all its
`compiled/` dirs across opt levels are stripped with
`decbench.utils.cfg.strip_system_headers` and written as
`sources/<project>/<tu>.c` (`<tu>` = the `.i` basename), **deduplicated by
stripped content** across opt levels (identical content → written once).

Manifests / index: after the walk it writes `dataset.toml` (§4) and
`configs/<name>/manifest.json` + filtered `function_results.json` for the five
non-full configs, plus `configs/full/manifest.json` (§3). Filtered scores come
from `decbench.scoring.subset.filter_function_data` (a `SubsetManifest`
restricted to the functions tagged with that preset).

It also **extends `.gitattributes`** in the dataset repo so the binary artifacts
are tracked by LFS (§6), never overwriting the HF-managed LFS lines already
there.

### CLI surface (`scripts/publish_dataset.py`)
```
python scripts/publish_dataset.py <results_dir> [--dest ~/github/decbench-dataset]
    [--cfgs] [--cfg-workers N]
    [--configs sample-set,large,unoptimized,optimized,inlined,full]
    [--only-config sample-set] [--skip-binaries] [--skip-results]
    [--skip-sources] [--max-binaries N]
```
It prints a summary (counts + bytes written per section). A no-`--cfgs` run
completes the whole layout except the CFG JSONs; `--max-binaries N` is a debug
knob that processes only the first N selected groups.

## 3. Config manifest schema — `configs/<name>/manifest.json`

Plain JSON (the consumer CLI parses it with stdlib `json`; the publisher may use
pydantic to write it). Every path is **repo-relative POSIX**. Self-contained: a
consumer can download exactly a config from this file alone.

```jsonc
{
  "config": "sample-set",
  "description": "~250 functions evenly sampled across unoptimized/optimized/inlined/large/ARM and projects",
  "dataset_repo": "noelo-lab/decbench-dataset",
  "created": "2026-07-04T00:00:00",            // ISO; stamped by publisher (not inside a workflow)
  "decompilers": ["angr","ghidra","ida","binja","kuna","r2dec","dewolf","codex","claude-code"],
  "metrics": ["byte_match","ged","type_match"],
  "function_count": 250,
  "binary_count": 250,
  "scores": "configs/sample-set/function_results.json",  // full: "results/function_results.json"
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
decompilers = ["angr","ghidra","ida","binja","kuna","r2dec","dewolf","codex","claude-code"]
metrics = ["byte_match","ged","type_match"]
projects = 40
binaries = 806
functions = 94716

[configs.sample-set]
description = "~250 functions evenly sampled across categories and projects"
function_count = 250
binary_count   = 250
manifest = "configs/sample-set/manifest.json"
scores   = "configs/sample-set/function_results.json"

[configs.unoptimized] # all O0 functions
...
[configs.optimized]   # optimized WITHOUT inlining (all O2-noinline functions)
...
[configs.inlined]     # optimized WITH inlining (all plain-O2 functions)
...
[configs.large]       # O2-noinline, large functions only (upper size tail)
...
[configs.full]        # everything
manifest = "configs/full/manifest.json"
scores   = "results/function_results.json"
```

Counts come from the actual walk (do not hardcode). Config descriptions mirror
`decbench.scoring.datasets.PRESETS`.

## 5. Source-CFG serialization — `pipeline_data/source_cfgs/<opt>/<project>/<stem>.json`

**GED is almost purely structural** — `cfgutils.similarity.vj_ged` (the
metric's engine) scores from graph topology (per-node parent/child counts via a
positional `GraphCache`) **plus** each node's `is_entrypoint` / `is_exitpoint`
flags (an entry/exit mismatch penalty); it never reads labels or any other
attribute. So a lossless serialization is the topology plus the entry/exit node
ids, and nothing else. Store, per binary, the `function → CFG` map the pipeline
used:

```jsonc
{
  "opt": "O0", "project": "zlib", "binary": "example",
  "generator": "pyjoern",                 // provenance
  "functions": {
    "test_compress": {
      "nodes": [0, 1, 2],                  // ints 0..n-1
      "edges": [[0,1],[1,2]],
      "entry": [0], "exit": [2],           // node ids carrying the entry/exit flags GED reads
      "labels": {"0": "<Block: None.0, 4 statements>"}   // optional, human-readable; not used by GED
    }
  }
}
```

`decbench/publish/cfg_export.py` builds it by reusing
`decbench.utils.cfg.extract_cfgs_from_source` on the binary's project `.i` files
at that opt level and merging into a per-opt union (last-writer-wins on name
collisions). Each DiGraph's nodes are relabeled to `0..n-1` (stable order) with
the entry/exit node ids recorded; Joern parses are **deduplicated by
stripped-content hash** so each unique translation unit is parsed once (Joern
spawns a JVM per parse — the dominant cost; see the module docstring), and an
existing `<stem>.json` is skipped. Note the pipeline itself no longer scores
against such a union: `pipeline/evaluate.py` matches TU-aware (a binary's OWN
translation unit first, cross-TU best-by-name only as fallback), so on a
cross-TU name collision the exported union may hold a different same-named body
than the one the stored GED was computed against.

A round-trip check (`cfg_export.rebuild_cfg` on a serialized function, run
`vj_ged` against a decompiled CFG, compare to the stored score in
`function_results.json`) matches for spot-checked functions, modulo the
name-collision caveat above.

## 6. `.gitattributes` (LFS)

The published binaries have no extension, so the publisher adds its own rules so
Git LFS tracks them without disturbing the HF defaults already present.
`layout.extend_gitattributes` appends these four rules idempotently, under an
`# added by decbench.publish` marker:
```
binaries/** filter=lfs diff=lfs merge=lfs -text
results/**/*.c -filter -diff -merge text
results/function_results.json filter=lfs diff=lfs merge=lfs -text
configs/**/function_results.json filter=lfs diff=lfs merge=lfs -text
```
Binaries under `binaries/**` are arbitrary ELF/PE → LFS. Decompiled C stays
normal git text so it diffs nicely, as do the other text artifacts
(`sources/**/*.c`, `pipeline_data/**/*.json`, the manifests, `dataset.toml`).
The score JSONs are the exception: the master `results/function_results.json`
(~165 MB) and the per-config `configs/**/function_results.json` (tens of MB for
broad configs like `unoptimized`) are too large for plain git, so they go
through LFS.

## 7. Consumer CLI (`decbench_data` — lives in the dataset repo)

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
- `decbench-data download <config> [--dest DIR] [--include ...]
  [--repo-path PATH] [--revision REV]` — resolve the config's `manifest.json`,
  then fetch every listed file (binaries, sources, source CFGs, decompiled
  results, scores) and lay them out under `DEST` **mirroring the repo layout**
  (so the result is directly analyzable and matches paths in the manifest).
  `--include` selects sections (`binaries,sources,cfgs,results,scores`);
  default = all. See the `decbench_data` package itself for its full flag
  surface.

Download mechanism: `huggingface_hub.hf_hub_download(repo_id=..., repo_type=
"dataset", filename=<repo-relative path>, revision=..., local_dir=DEST)` per file
so only the config's subset is transferred (never the whole repo). Verify sha256
for binaries when present in the manifest. Show progress; be resumable (skip
files already present with matching size/sha).

**Local fallback for offline/testing**: if `--repo-path PATH` is given, read
`dataset.toml` / manifests / files from that local directory by copying instead
of hitting the hub. This lets the CLI be verified against a freshly-populated
repo before anything is pushed to HF.

A tiny quickstart in the CLI package (`decbench_data/README.md` or docstring):
```
pip install decbench-data           # or: pip install git+https://huggingface.co/datasets/noelo-lab/decbench-dataset
decbench-data list
decbench-data download sample-set --dest ./decbench-sample-set
```

## 8. `decbench download` alias (`decbench/cli.py`)

The main decbench CLI carries a thin top-level `download` command, so existing
users get `decbench download sample-set`. It duplicates no logic: it lazily
imports the `decbench_data` package and delegates to it (forwarding `--dest` /
`--repo-path` / `--include` / `--revision`), printing a one-line install hint
(`pip install decbench-data`) when the package isn't there. The heavy decbench
imports stay lazy so `decbench download` works even in a minimal environment.

## 8b. Materializing a config back into a results tree

A downloaded config mirrors the *repo* layout, which is not what the pipeline
consumes. The consumer CLI converts it:

```bash
decbench-data materialize sample-set --dest ./tree     # hub (or --repo-path)
decbench evaluate-tree ./tree -m ged                   # score stored artifacts
```

`materialize` lays the config out as a decbench results tree —
`<opt>/<project>/compiled/<binary>`, `decompiled/<dec>_<stem>.c` (+ sibling
`.toml` when published), and `source_cfgs/<stem>.json` (the published source
CFGs) — plus the config's scores as `materialized_scores.json` and a
`materialized.json` provenance stub. `--max-binaries N` limits a smoke run;
`-d NAME` filters decompilers.

On the tool side, `decbench evaluate-tree TREE` (and `decbench run
--skip-compile --skip-decompile --source-cfgs TREE`) evaluates such a tree:
stored `<dec>_<stem>.c` artifacts are loaded back into `DecompilationResult`s
(`decbench.pipeline.materialized`), and source CFGs come from the published
JSONs via `publish.cfg_export.rebuild_cfg` instead of `.i` extraction (the
dataset ships no `.i`). GED and byte_match evaluate fully; **type_match does
not** (published artifacts carry no `VariableInfo`). This is the supported
path for scoring a *new* decompiler against the published binaries: decompile
the `compiled/` binaries into `decompiled/<newdec>_<stem>.c` (with the
pipeline or your own tooling emitting the `// Function: <name> @ 0x<addr>`
markers), then `evaluate-tree`.

## 9. Verifying a publish

A quick end-to-end check after (re)publishing:
```
python scripts/publish_dataset.py results/full_run --only-config sample-set --cfgs
decbench-data download sample-set --repo-path ~/github/decbench-dataset --dest /tmp/decbench-ss
decbench-data list && decbench-data info sample-set   # counts should match dataset.toml
```
The download lays out the slice's binaries + sources + CFGs + scores with sha256
verified (`decbench download sample-set` reaches the same code path). Nothing is
ever pushed to HF automatically; `git add/commit/push` is left to the user.
