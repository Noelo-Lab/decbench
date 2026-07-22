# DecBench site data schema

The site is a static SPA whose every aggregate view is **precomputed server-side**.
Nothing per-function is shipped except the bounded, code-carrying `samples` list.

## Why precomputed

Every aggregate the report renders is a pure function of two selectors — the **dataset
preset** (`unoptimized` / `optimized` / `inlined` / `large` / `sample-set`) and the
**normalize-failures** toggle — so all `5 x 2 = 10` combinations are computed once, at
build time (rationale and measurements: CLAUDE.md's "Why precompute").

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
├── insights/index.html     #   url(#marker) refs and #anchors). Makes /leaderboard/,
├── changelog/index.html    #   /distance/, ... directly linkable and reload-safe.
├── about/index.html        #   (insights + changelog are prose-only views.)
├── CNAME                   # custom domain (from site.toml [pages].domain)
├── favicon.png             # 64x64 tab icon      \ vendored under
├── apple-touch-icon.png    # 180x180 iOS icon    | assets/icons/, derived
├── decbench_card.png       # 1200x630 OG/Twitter share image  / from decbench_icon.png
├── fonts/                  # vendored Source Code Pro woff2 (offline render)
└── data/
    ├── aggregates.json # the 10 combos + registry. Loaded eagerly.
    ├── dataset.json    # About page (corpus tables). Corpus-wide, selector-independent.
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

## Favicon and social share metadata

Three PNGs are vendored under `decbench/rendering/assets/icons/` (alongside the fonts,
for the same offline-render reason) and derived from `assets/decbench_icon.png`: a
64x64 `favicon.png`, a 180x180 `apple-touch-icon.png`, and the 1200x630
`decbench_card.png` Open Graph / Twitter share image (a black terminal card with the
CFG mark, the `DecBench` wordmark, and `decbench.com`). `build_site` copies all three
to the tree root; regenerate them with the PIL scripts noted in the commit that added
them, not by hand.

**Favicon links** ship in both delivery modes (`html.py`'s `PageAssets`). The split
site links the files (`<link rel="icon" href="{root}favicon.png">` plus an
apple-touch link, the `{root}` hop `""` at the root and `../` on a subpage); the
single-file report links a small 32x32 favicon as an inline `data:` URI (`favicon-32.png`,
never written as a file) so it stays self-contained and light.

**Open Graph / Twitter tags** are baked into each page's `<head>` **at build time** —
crawlers read static HTML and never run `app.js`, so nothing derived client-side would
be seen. They are emitted **only** when `site.toml`'s `[pages] domain` is set (the tags
need absolute URLs); a domain-less build omits them and crawlers fall back to the
`<title>`. Per page: `og:site_name` (DecBench), `og:type` (website), `og:title`
(`DecBench — <view>`, or `DecBench — decompiler benchmark` at the root), `og:description`,
`og:url` (that page's own canonical URL — `https://<domain>/` at the root, `…/<view>/`
on a subpage), `og:image` (the absolute `decbench_card.png`) with `og:image:width`/
`height`, and the `twitter:card=summary_large_image` / `twitter:title` / `twitter:description`
/ `twitter:image` mirror. The **single-file report emits none** — it is shared as a file,
not a crawlable URL.

The per-page `og:description` is derived from the freshly-computed `aggregates` payload
(so `build_site` computes payloads first, then pages): the leaderboard/distance text
quotes the default-preset **top-3 by Union** over the on-screen decompilers
(`aggregate.union_leaders`, excluding the sample-set-only backends), the view page
quotes the sample-set top-3 (all decompilers), and each is kept ≤ 200 chars. Escaped
with `html.escape`.

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

**Theme.** The light/dark choice is NOT part of the SPA state above: it is applied
before `app.js` runs, by the tiny bootstrap script in every page's `<head>` (see
`html.py`'s `_THEME_BOOTSTRAP`). Dark is the default; the bootstrap reads
`localStorage['decbench-theme']` (`"light"`/`"dark"`) and stamps `data-theme` on
`<html>` before first paint, so there is no flash. An optional **`?theme=light`** (or
`?theme=dark`) query param overrides the stored value — a debug/share convenience that
is also *persisted* to `localStorage`, so a shared `?theme=light` link keeps light mode
on subsequent navigation. There is deliberately no OS-preference (`prefers-color-scheme`)
detection: only an explicit choice switches. The sidebar `[ light mode ]`/`[ dark mode ]`
button (`#theme-toggle`) flips and persists it at runtime.

## `data/aggregates.json`

```jsonc
{
  "name": "sailr_full",                  // scoreboard name
  "version": "0.1.0",
  "generated_at": "2026-07-15T15:28:00", // ISO 8601
  "projects_evaluated": ["bash", "..."],
  "decompilers": ["angr", "binja", "claude-code", "codex", "dewolf", "ghidra", "ida",
                  "kuna", "r2dec"],               // site-visible only (hidden stripped)
  "sample_set_only": ["claude-code", "codex"],    // rows shown only on the sample-set preset
  "decompiler_versions": {"ghidra@12.1": "12.1"},  // id -> raw version (back-compat)
  "decompiler_registry": {                         // id -> presentation (see below)
    "angr": {"display_name": "angr", "url": "https://angr.io",
             "license": "open-source", "logo": true, "version": "9.2.223"},
    "ida":  {"display_name": "Hex-Rays", "url": "https://hex-rays.com/ida-pro/",
             "license": "closed-source", "logo": true, "version": "9.2"}
  },
  "metrics": ["ged", "type_match", "byte_match"],  // as present in the run
  "metric_registry": {                             // metric -> on-screen name + order
    "ged": {"display_name": "Structural Correctness (GED)", "short_name": "Structure",
            "order": 1}                            //   (from content/metrics.toml)
  },
  "presets": [
    // `long_description` is the leaderboard's per-dataset explainer (final inline
    // HTML from content/datasets.toml; "" when the registry has none for it).
    {"name": "unoptimized", "label": "unoptimized", "description": "...",
     "long_description": "...", "default": true}
  ],
  "default_view": "leaderboard",                   // views.toml's `default = true`
  "totals": {"functions": 91483, "binaries": 806},  // corpus-wide, all presets

  // Key: "<preset>|<normalize>" where normalize is "0" or "1".
  // A run with NO presets emits `"presets": []` plus the single reserved combo pair
  // "__all__|0" / "__all__|1" over the whole corpus (see "No presets" below).
  "combos": {
    "unoptimized|0": {
      "functions": 91483,          // active under this combo (sidebar counter)
      "binaries": 806,             // binaries with >=1 active function
      "per_metric": {              // decompiler -> metric -> [perfect, total]
        "angr": {"ged": [12345, 67890], "type_match": [1, 2], "byte_match": [3, 4]}
      },
      "overall": {"angr": [111, 222]},   // Union column: decompiler -> [perfect, total]
      "errors":  {"angr": [5, 1000]},    // decompiler -> [errored, scope]
      "compile": {"angr": [890, 1000]},  // Compiles rate (distance page): decompiler -> [compiled, byte_match-measured]
      "distance": {                      // decompiler -> metric -> stats | null
        "angr": {"ged": {"mean": 3.25, "median": 2, "n": 5000, "at0": 1200}}
      }
    }
    // ... 9 more
  }
}
```

`per_metric`, `overall`, `errors` and `compile` are `[numerator, denominator]` pairs,
not percentages: the UI renders `count/total` next to the bar, and computing the
percentage client-side keeps the JSON small and lossless.

`distance[dec][metric]` is `null` when no function under the combo had a finite
distance for that metric.

### Decompiler registry

`decompiler_registry` maps each decompiler id to how it is shown — `display_name`,
an optional `url` (a project homepage; the client renders a link when present,
`target=_blank rel=noopener`), an optional prettified `version`, an optional
`license` (`"open-source"` / `"closed-source"`), and an optional `logo` flag. The
client (`app.js`'s `decName`/`decUrl`/`decVersion`/`decHasLogo`) renders
these in place of raw ids in the leaderboard, the metrics table, the distance page's
distance and compile tables, and the view page's decompiler dropdown; name-sorting sorts
by `display_name`. It is **tolerant**: a missing registry, or an id with no entry, falls
back to the raw id (unlinked), exactly like `metric_registry`.

The **leaderboard name cell only** renders as a stacked block — the logo-prefixed
(linked) name, then the version on its own line. The other tables keep the compact
inline `name vX` form (one `decNameHtml(id, {stacked})` with an options arg serves
both). `logo` marks that `app.css` ships a self-contained `.dlogo-<base>` background
for that id (grayscale at rest, full colour on row hover), consumed when `app.js`'s
`SHOW_LOGOS` flag is on (it ships on). `license` is emitted for consumers but not
rendered anywhere. Both fields are emitted only when set, so the payload stays
minimal.

The presentation comes from `decbench/rendering/content/decompilers.toml`. The
`version` is `decompiler_versions[id]` passed through that entry's `version_overrides`
(e.g. IDA's raw `"920"` → `"9.2"`), prettified **server-side** so the client renders
it verbatim; the raw `decompiler_versions` map is kept for back-compat. Lookup is by
exact id, then base name before `@`, so a versioned id (`ghidra@12.1`) resolves to the
`ghidra` entry. The registry is keyed by `decompilers` — the same list, already
stripped of site-hidden backends — so it can never reintroduce a hidden decompiler.

### No presets (`__all__`)

Dataset preset tagging is best-effort (`cli.py`'s `report` swallows any
`scoring.datasets.assign_datasets` failure). When a `FunctionData` carries no presets,
the builder emits `"presets": []` and one synthetic combo pair under the reserved
preset name `__all__`, which every function is active under. Empty `presets` means no
dataset selector renders; the client (`app.js`'s `FALLBACK_PRESET`) selects `__all__`,
so the site shows the full corpus, selector-less. `__all__` is reserved — a real
preset must never use the name.

### Float precision

Floats are emitted **exactly as computed** — no rounding, deliberately. Values were
once rounded to 3dp; that double-rounded against the client's coarser `toFixed()`
renderings (flipping real cells in both directions) and bought ~0.087% of payload size.
Any future rounding is only correct at a precision >= the most precise rendering the
client performs — an unenforceable Python/JS coupling, so don't (history:
`aggregate.py`).

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
* `compile` is the **Compiles** rate: `[# whose decompiled C recompiled, #
  where byte_match was measured]`. The denominator is per-decompiler (functions
  where that decompiler has a byte_match value — decompiled AND the target arch
  had a recompile toolchain), so ARM/PE abstentions never enter it. This is the
  compilability-fixup success rate, and it moves with the dataset preset like the
  metric columns (O0 code compiles more readily than O2). It is rendered in its
  own `#compile-table` on the **distance** page (it used to be a leaderboard
  column); the combo key is unchanged.
* `normalize=1` additionally restricts to functions **every** decompiler decompiled —
  where "every" means every decompiler *whose rows the preset shows*: the
  sample-set-only backends (`sample_set_only`, e.g. codex/claude-code) attempt nothing
  outside the sample-set slice, so they join the gate only on the sample-set preset and
  are ignored elsewhere (`aggregate._active_combos`).

## `data/dataset.json`

```jsonc
{
  "summary": {
    "projects": 40, "unique_binaries": 266, "builds": 806,
    "functions": 91483, "total_loc": 0
  },
  "categories": [{"name": "parser", "count": 12}],   // ordered; count = #projects
  "projects": [
    // `presets`: which dataset presets this project participates in (>=1 of its
    // functions carries that preset tag), in selector order. The About page's
    // projects table filters on it: the sample-set preset lists only projects
    // whose `presets` include "sample-set"; other presets show the full list.
    {"name": "bash", "cats": ["parser"], "loc": 12345, "binaries": 3,
     "functions": 456, "presets": ["unoptimized", "optimized", "inlined", "sample-set"]}
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

## `data/samples.json`

Serialized straight from `FunctionData.samples`
(`decbench/models/function_data.py`) — every *finite* float exactly as measured. Values
that could not be measured are stored as `Infinity` upstream; browsers' strict
`JSON.parse` rejects that token, so non-finite sample metric values are dropped at build
time (`aggregate._finite_sample`), and the JSON writer runs with `allow_nan=False` so
anything else non-finite fails the build loudly. Finite values are never rounded on the
way out (see "Float precision" above). `FunctionData.hardest` and `.history` are still
*stored* but no longer shipped — the View page's `hard` tier replaced the Hardest view,
and the Historical view was removed outright (its `history.json` payload and
`history/index.html` subpage are gone).

Each entry's `difficulty` is one of `easy` / `medium` / `hard` — the GED-agreement
tiers built at benchmark time (`scoring/view_samples.py`) — or `sample-set`, the
dataset selector's curated slice, materialized at *site-build* time by
`decbench site build` (one entry per function tagged `sample-set` in
`FunctionRecord.datasets`, code read from the results tree's `decompiled/*.c`
artifacts — `scoring/report_extras.build_sample_set_samples`). The View page lists
each tier as a dropdown option; the `sample-set` entries are what surface the
sample-set-only backends (e.g. codex) there. A function may appear both in its GED
tier and as a separate `sample-set` entry — they are distinct records.

`samples.json` (a few MB of embedded C source) is the site's size floor — the view
exists to *show the code*. It is fetched lazily, so it costs nothing until the reader
opens that page.

Malware targets are **excluded** from both payloads at build time
(`scoring/report_extras.py`), because publishing them is what these files would
otherwise do — see the note there. They still count in every score.
