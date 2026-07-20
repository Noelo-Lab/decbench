# DecBench site data schema

The site is a static SPA whose every aggregate view is **precomputed server-side**.
Nothing per-function is shipped except the bounded, code-carrying `samples` list
(the old `hardest` payload was absorbed into `samples`' `hard` difficulty tier).

## Why precomputed

Every aggregate the report renders is a pure function of two selectors:

* the **dataset preset** (`unoptimized` / `optimized` / `inlined` / `large` / `sample-set`)
* the **normalize-failures** toggle (on / off)

That is `5 x 2 = 10` combinations. The old report shipped all 91,483 `FunctionRecord`s
(~98 MB) so the browser could recompute those same 10 tables on every click. We compute
them once, at build time, into ~22 KB.

Consequence: adding a *new* client-side filter dimension requires a re-render
(`decbench site build`), not just a page reload. That is the deliberate trade.

## Layout

```
site/
├── index.html          # shell: skeleton + prose, no data (opens on the default view)
├── app.css
├── app.js
├── .nojekyll           # stop Pages from running Jekyll over the tree
├── leaderboard/index.html  # one subpage per VISIBLE view: the same skeleton, that
├── distance/index.html     #   view marked active and its asset links prefixed with
├── view/index.html         #   "../" (no <base> — that would break same-document SVG
├── history/index.html      #   url(#marker) refs and #anchors). Makes /leaderboard/,
├── about/index.html        #   /distance/, ... directly linkable and reload-safe.
└── data/
    ├── aggregates.json # the 10 combos + registry. Loaded eagerly.
    ├── dataset.json    # Dataset page. Corpus-wide, selector-independent.
    ├── history.json    # Historical page.
    └── samples.json    # View page. Lazy — fetched on first view.
```

Every page carries the comment marker `<!-- decbench:page -->`. On rebuild the writer
prunes a subdirectory left by a removed/renamed view, but **only** when its
`index.html` carries that marker — never an arbitrary directory (a `CNAME` folder, a
hand-added page) a maintainer dropped in `site/`. `data/` and `fonts/` are wholly
regenerated and wiped first.

`index.html` in **single-file mode** (`decbench report`) inlines every asset and every
data file into one HTML document, so it still opens over `file://` where `fetch()` is
CORS-blocked. The JS branches on `window.__DECBENCH_INLINE__` and skips fetching. A
single-file report has no subpage tree and no routing root (below).

## Routing and URL state

The site is one SPA rendered under several URLs, so a view and a data configuration
are both linkable.

**View routing.** Each split page stamps `window.__DECBENCH_ROOT__` — the relative hop
to the site root (`""` on `index.html`, `"../"` on a subpage) — in an inline script
*before* `app.js`, which is how the client tells split mode from the inline report
(where it is undefined) and computes the site root for `pushState` targets. In split
mode a nav click `pushState`s to `<root><view>/` and back/forward re-route from the
path; a fresh load resolves a valid legacy `#hash` first (so old `site/#about` links
keep working), otherwise the renderer already marked the right section active. The
single-file report keeps pure `#hash` routing. All `history` calls are wrapped in
`try/catch` for `file://`.

**State in query params** (read once at init, written with `replaceState` on every
change — never a new history entry), both modes:

* `dataset=<preset>` — a selectable preset name; omitted from the URL when it is the
  default preset.
* `norm=1` — normalize-failures on (absent/`0` = off).
* view page only: `tier=easy|medium|hard`, `dec=<decompiler id>`, `metric=<metric>`,
  and `fn=<project>/<opt>/<binary>::<function>` (the selected function). These are
  written only while the view page is open.

Unknown or invalid values fall back silently to defaults — never an error banner.

## `data/aggregates.json`

```jsonc
{
  "name": "sailr_full",                  // scoreboard name
  "version": "0.1.0",
  "generated_at": "2026-07-15T15:28:00", // ISO 8601
  "projects_evaluated": ["bash", "..."],
  "decompilers": ["angr", "binja", "ghidra", "ida", "kuna", "phoenix"],
  "decompiler_versions": {"ghidra@12.1": "12.1"},  // id -> raw version (back-compat)
  "decompiler_registry": {                         // id -> presentation (see below)
    "angr": {"display_name": "angr", "url": "https://angr.io",
             "license": "open-source", "logo": true, "version": "9.2.223"},
    "ida":  {"display_name": "Hex-Rays", "url": "https://hex-rays.com/ida-pro/",
             "license": "closed-source", "logo": true, "version": "9.2"}
  },
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
      "overall": {"angr": [111, 222]},   // Union column: decompiler -> [perfect, total]
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

### Decompiler registry

`decompiler_registry` maps each decompiler id to how it is shown — `display_name`,
an optional `url` (a project homepage; the client renders a link when present,
`target=_blank rel=noopener`), an optional prettified `version`, an optional
`license` (`"open-source"` / `"closed-source"`), and an optional `logo` flag. The
client (`app.js`'s `decName`/`decUrl`/`decVersion`/`decLicense`/`decHasLogo`) renders
these in place of raw ids in the leaderboard, the metrics table, the distance table,
the view page's decompiler dropdown, and the historical legend; name-sorting sorts by
`display_name`. It is **tolerant**: a missing registry, or an id with no entry, falls
back to the raw id (unlinked), exactly like `metric_registry`.

Two of these fields drive the **leaderboard name cell only**, which renders as a
stacked block — the (linked) name, then the version, then the `license` tag (subtly
colour-coded, muted green/amber, per `.lic-*` in `app.css`). The other tables keep the
compact inline `name vX` form (one `decNameHtml(id, {stacked})` with an options arg
serves both). `logo` marks that `app.css` ships a self-contained `.dlogo-<base>`
background for that id; it is consumed only when `app.js`'s `SHOW_LOGOS` flag is on,
which prepends a small logo to the stacked name line. `SHOW_LOGOS` ships **off** — the
logos read as noise on the mono terminal page — so `logo` is inert by default. Both
fields are emitted only when set (absent = no tag / no logo), so the payload stays
minimal, and both come from `decbench/rendering/content/decompilers.toml`.

The presentation comes from `decbench/rendering/content/decompilers.toml`. The
`version` is `decompiler_versions[id]` passed through that entry's `version_overrides`
(e.g. IDA's raw `"920"` → `"9.2"`), prettified **server-side** so the client renders
it verbatim; the raw `decompiler_versions` map is kept for back-compat. Lookup is by
exact id, then base name before `@`, so a versioned id (`ghidra@12.1`) resolves to the
`ghidra` entry. The registry is keyed by `decompilers` — the same list, already
stripped of site-hidden backends — so it can never reintroduce a hidden decompiler.

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
* `overall` is the **Union** column (the key name is legacy): a function is in the
  denominator iff *at least one* metric is measurable for it, and in a decompiler's
  numerator iff that decompiler is perfect on at least one of those measurable
  metrics. (Until 2026-07 this key was Overall — perfect on ALL metrics, over
  functions where every metric was measurable.)
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

## `data/samples.json` / `data/history.json`

Serialized straight from `FunctionData.samples`, `.history`
(`decbench/models/function_data.py`) — every *finite* float exactly as measured. Values
that could not be measured are stored as `Infinity` upstream; browsers' strict
`JSON.parse` rejects that token, so non-finite sample metric values are dropped and
non-finite history points nulled at build time (`aggregate._finite_sample` /
`_finite_history`), and both JSON writers run with `allow_nan=False` so anything else
non-finite fails the build loudly. Finite values are never rounded on the way out (see
"Float precision" above). `FunctionData.hardest` is still *stored* but no longer
shipped — the View page's `hard` tier replaced it.

`samples.json` (a few MB of embedded C source) is the site's size floor — the view
exists to *show the code*. It is fetched lazily, so it costs nothing until the reader
opens that page.

Malware targets are **excluded** from both payloads at build time
(`scoring/report_extras.py`), because publishing them is what these files would
otherwise do — see the note there. They still count in every score.
