# DecBench site data schema

The site is a static SPA whose every aggregate view is **precomputed server-side**.
Nothing per-function is shipped except the two bounded, code-carrying lists
(`samples`, `hardest`).

## Why precomputed

Every aggregate the report renders is a pure function of two selectors:

* the **dataset preset** (`full` / `hard` / `hard-inlined` / `unoptimized` / `tiny`)
* the **normalize-failures** toggle (on / off)

That is `5 x 2 = 10` combinations. The old report shipped all 91,483 `FunctionRecord`s
(~98 MB) so the browser could recompute those same 10 tables on every click. We compute
them once, at build time, into ~22 KB.

Consequence: adding a *new* client-side filter dimension requires a re-render
(`decbench site build`), not just a page reload. That is the deliberate trade.

## Layout

```
site/
├── index.html          # shell: skeleton + prose, no data
├── app.css
├── app.js
├── .nojekyll           # stop Pages from running Jekyll over the tree
└── data/
    ├── aggregates.json # the 10 combos + registry. Loaded eagerly.
    ├── dataset.json    # Dataset page. Corpus-wide, selector-independent.
    ├── history.json    # Historical page.
    ├── samples.json    # Compare page. Lazy — fetched on first view.
    └── hardest.json    # Hardest page. Lazy — fetched on first view.
```

`index.html` in **single-file mode** (`decbench report`) inlines every asset and every
data file into one HTML document, so it still opens over `file://` where `fetch()` is
CORS-blocked. The JS branches on `window.__DECBENCH_INLINE__` and skips fetching.

## `data/aggregates.json`

```jsonc
{
  "name": "sailr_full",                  // scoreboard name
  "version": "0.1.0",
  "generated_at": "2026-07-15T15:28:00", // ISO 8601
  "projects_evaluated": ["bash", "..."],
  "decompilers": ["angr", "binja", "ghidra", "ida", "kuna", "phoenix"],
  "decompiler_versions": {"ghidra@12.1": "12.1"},  // id -> display version
  "metrics": ["ged", "type_match", "byte_match"],  // as present in the run
  "presets": [
    {"name": "full", "label": "full", "description": "...", "default": true}
  ],
  "totals": {"functions": 91483, "binaries": 806},  // corpus-wide, all presets

  // Key: "<preset>|<normalize>" where normalize is "0" or "1".
  // A run with NO presets emits `"presets": []` plus the single reserved combo pair
  // "__all__|0" / "__all__|1" over the whole corpus (see "No presets" below).
  "combos": {
    "full|0": {
      "functions": 91483,          // active under this combo (sidebar counter)
      "binaries": 806,             // binaries with >=1 active function
      "per_metric": {              // decompiler -> metric -> [perfect, total]
        "angr": {"ged": [12345, 67890], "type_match": [1, 2], "byte_match": [3, 4]}
      },
      "overall": {"angr": [111, 222]},   // decompiler -> [perfect, total]
      "errors":  {"angr": [5, 1000]},    // decompiler -> [errored, scope]
      "distance": {                      // decompiler -> metric -> stats | null
        "angr": {"ged": {"mean": 3.25, "median": 2, "n": 5000, "at0": 1200}}
      }
    }
    // ... 9 more
  }
}
```

`per_metric`, `overall` and `errors` are `[numerator, denominator]` pairs, not
percentages: the UI renders `perfect/total` counts next to the bar, and computing the
percentage client-side keeps the JSON small and lossless.

`distance[dec][metric]` is `null` when no function under the combo had a finite
distance for that metric.

### No presets (`__all__`)

Dataset presets are membership tags applied after the benchmark by
`scoring.datasets.assign_datasets`, and tagging is best-effort — `cli.py`'s `report`
swallows any failure. When a `FunctionData` carries none, the builder emits `"presets":
[]` and one synthetic combo pair under the reserved preset name `__all__`, which every
function is active under. `presets` staying empty means no dataset selector renders;
the client (`app.js`'s `FALLBACK_PRESET`) selects `__all__` when it has no preset, so
the site shows the full corpus, selector-less. This reproduces the pre-aggregation
client, whose `isActive()` began `if (!state.dataset) return true;`. `__all__` is
reserved — a real preset must never use the name.

### Float precision

Floats are emitted **exactly as computed** — no rounding, deliberately.

They used to be rounded to 3dp, documented as lossless. That was **wrong**. The proof
covered only means and perfect flags, but the client re-renders some values at *fewer*
places than the file stores: `toFixed(2)` for Compare's per-function values
(`app.js`), `toFixed(1)` for distance means. Pre-rounding manufactures an exact
half-boundary at the rendered precision, and the second rounding breaks that tie the
other way — `0.45454...` renders `0.45`, but stored as `0.455` it renders `0.46`.
Measured on the full run: **13 Compare cells and 1 distance cell changed, in both
directions**.

Rounding was a size optimization that bought **0.087%** (6.4 KB of 7.3 MB; 2.1 KB of
935 KB gzipped) — these payloads are dominated by embedded C source, not float digits.
It is deleted rather than re-proved. Any future rounding is only correct at a precision
>= the most precise rendering the client performs, which is a coupling across the
Python/JS boundary that no test in this repo can enforce. Don't.

### Denominator semantics (must not drift)

These rules are ported verbatim from the old client-side `recompute()`. They are the
benchmark's fairness contract:

* A metric is **measurable** for a function iff *some* decompiler got a finite value for
  it (for `ged`, that is `sourceParsed`). Unmeasurable-for-everyone functions leave every
  decompiler's denominator — uniformly.
* A function that IS measurable but which a given decompiler failed on counts as that
  decompiler's **not-perfect miss**. It is not dropped from the denominator.
* `overall` counts only functions where *every* metric is measurable.
* `errors.scope` = functions the decompiler attempted (present in `decompiled`);
  `errors.errored` = those where it produced nothing.
* `normalize=1` additionally restricts to functions **every** decompiler decompiled.

## `data/dataset.json`

```jsonc
{
  "summary": {
    "projects": 40, "unique_binaries": 266, "builds": 806,
    "functions": 91483, "total_loc": 0
  },
  "categories": [{"name": "parser", "count": 12}],   // ordered; count = #projects
  "projects": [
    {"name": "bash", "cats": ["parser"], "loc": 12345, "binaries": 3, "functions": 456}
  ],
  "joern": {
    "source": {"lost": 100, "total": 91483},   // GED unmeasurable: our source front-end
    "output": {"angr": [12, 3456]},            // dec -> [failed, scope]
    "spot_check": {"files_sampled": 0, "files_failed": 0, "files_timed_out": 0}
  }
}
```

`categories` and each project's `cats` are resolved at build time from the taxonomy in
`decbench/rendering/content/categories.toml` against per-binary labels.

## `data/samples.json` / `data/hardest.json` / `data/history.json`

Serialized straight from `FunctionData.samples`, `.hardest`, `.history`
(`decbench/models/function_data.py`) — every float exactly as measured. These carry the
per-function metric values the Compare view prints via `toFixed(2)`, which is precisely
why they are not rounded on the way out (see "Float precision" above).

These are the site's size floor — `hardest.json` 4.8 MB + `samples.json` 2.0 MB of
embedded C source — because both views exist to *show the code*. They are fetched
lazily, so they cost nothing until the reader opens those pages.

Malware targets are **excluded** from both payloads at build time
(`scoring/report_extras.py`), because publishing them is what these files would
otherwise do — see the note there. They still count in every score.
