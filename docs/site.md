# The report and the site — rendering architecture + data schema

`decbench/rendering/` produces both the single-file HTML report
(`decbench report`) and the deployable GitHub Pages tree
(`decbench site build`). This doc covers the rendering architecture, the
build/deploy flow, and — in the second half — the **normative data contract**
for the deployed tree.

## Rendering architecture (`decbench/rendering/`)

Themed after mahaloz.re (terminal aesthetic: black bg, Source Code Pro mono,
dashed rules, ASCII bars). `html.py` is **skeleton assembly only** — it holds
NO CSS, NO JS, NO prose. Layout:

- `content/` — **ALL maintainer-editable text.** `<view>.md` per view
  (leaderboard, **data**, **view**, changelog, **about**) + `site.toml`
  (brand/footer/banners/sidebar/side_stats, and `[decompilers] hidden` = the
  site-hidden decompilers, currently Phoenix), `views.toml` (view registry: id, nav label,
  `requires_function_data`, which is `default`), `metrics.toml` (display
  name/short name/order/perfect definition — the ONE source of truth),
  `datasets.toml` (the 5 presets' label+description+`default`),
  `categories.toml` (software-type taxonomy), `pricing.toml` (per-model
  USD/MTok list prices for the cost table — applied at RENDER time against
  `FunctionData.cost_info`'s token facts, so a price fix is a re-render;
  ships all-zero PLACEHOLDER cards that render n/a until the maintainer fills
  them in), PLUS `decompilers.toml` — the decompiler registry (id → official
  display_name/url/version_overrides, e.g. ida→"Hex-Rays" + "920"→"9.2");
  shipped into `aggregates.json` as `decompiler_registry` (hidden decompilers
  gated out), rendered as linked names + versions everywhere `app.js` names a
  decompiler. Loaded by `content.py` (`load_content()`) into frozen
  dataclasses.
- `assets/` — `app.css`, `app.js`, and a **vendored** Source Code Pro woff2
  (no Google Fonts CDN — the report must render offline). The scaffold's
  element ids (`leaderboard-table`, `view-<id>`, ...) are the contract with
  `app.js`; renaming one silently blanks a view. `app.js` also carries a
  self-contained C/asm syntax highlighter (`hlC`/`hlAsm`/
  `applyStaticHighlights`; token classes `tok-*` in app.css) — every
  `<pre data-lang="c|asm">` in static content and the view page's code panels
  are highlighted with it; NO third-party highlighter.
- `aggregate.py` — **precomputes every aggregate at BUILD time.** Every view
  is a pure function of exactly 2 selectors (dataset preset × normalize-
  failures toggle) = 5×2 = **10 combos**, keyed `"<preset>|<0|1>"`. Semantics
  are ported *verbatim* from the old client-side `recompute()`/
  `buildDistance()`/`buildDataset()` — they are the **fairness contract**
  (shared denominators), and JS quirks are reproduced on purpose (marked
  `JS parity`, e.g. global `isFinite(null) === true`). A "fix" here silently
  moves published numbers.
- `site.py` — the split Pages tree (`build_site`); its only writer.
- Two delivery modes share ONE skeleton (`build_page`) — the only difference
  is the `PageAssets` passed in: **inline** (`decbench report`, everything
  embedded because `file://` CORS-blocks `fetch()`) vs **split**
  (`decbench site build`, linked assets + lazy payloads).

**View history** (for anyone confused by old names): the view set was
consolidated — the old `metrics` + `dataset` views merged into **about**
(which carries the metric goal cards with collapsible SVG visualizations AND
the dataset tables), and `compare` + `hardest` merged into **view** (source vs
one decompiler across easy/medium/hard difficulty tiers —
`scoring/view_samples.py`; ~100 samples/tier in `samples.json`, and
`hardest.json` is no longer shipped). The 5 presets are `unoptimized`
(default) / `optimized` (O2-noinline) / `inlined` (O2) / `large` /
`sample-set` (250 fns; `scoring/datasets.py`). The old **distance** view is
now the **data** view (2026-07-23) with four linkable sections — distance,
compiles (the Compiles rate renders there), pipeline health (moved from
about), and cost (per-fn decompile time + estimated LLM $, facts gathered by
`scoring/cost.py` into `FunctionData.cost_info` via
`scripts/compute_cost_info.py`); old `/distance/` URLs and `#distance` hashes
redirect. The old Historical view was removed 2026-07-22 (HistoryPoint data +
`ingest_history.py` remain, just unshipped).

Content rules:

- A view's `id` MUST have a matching `<id>.md`; exactly one view and one
  preset must set `default = true` (`tests/test_content.py` enforces both).
- **Raw-HTML islands**: `<details class="metric-viz">...</details>` blocks
  pass through markdown VERBATIM (`content.py _render_with_islands` — mistune
  would otherwise wrap SVG children in `<p>` inside `<svg>`, which browsers
  refuse to draw, silently breaking the about page). No line inside an island
  may start with `# `/`## `; blank lines are fine.
- Editing `datasets.toml`/`metrics.toml` (preset labels + descriptions,
  metric names, perfect definitions) takes effect on **re-render alone — no
  benchmark re-run**: preset *text* is content, while preset *membership* is
  scoring (`scoring/datasets.py`), joined at render time. Adding a new
  client-side **filter dimension** is the exception — aggregates are
  precomputed per (preset × normalize) combo, so that needs a re-render
  (`decbench site build`), not just a page reload.

**Labels** are derived by `scoring/labels.py`: auto opt-level labels (`O0`/
`O2` + `optimized`/`unoptimized`), project labels from `ProjectConfig.labels`
/ `binary_labels` (TOML), and per-function auto labels (`large` ≥ 100
decompiled lines — distinct from the `large` *preset*, which is the
size-bell-curve upper tail in `scoring/datasets.py`).

**Preset membership** is tagged server-side by `scoring/datasets.py`
(`assign_datasets`; "large" = upper tail of the size bell curve). The
code-carrying extras (`samples`, `hardest`, `compile_rates`) are built by
`scoring/report_extras.py` (`build_samples`/`build_hardest`/
`compute_compile_rates`, wired in `attach_extras` AFTER datasets are
assigned). Models in `models/function_data.py` (`SampleEntry`,
`compile_rates`).

### Why precompute

The old report embedded every `FunctionRecord` — ~98.5 MB of JSON the browser
re-scanned on every click — and a fresh single-file report exceeded GitHub's
**100 MiB** per-file push limit, so it could not be committed at all.
Precomputing the 10 combos shrinks `aggregates.json` to tens of KiB. Only
`samples.json` and `dataset.json` are fetched lazily, when their view opens.

## Site build + deploy

Two commands render the **same page** from the same skeleton and the same
content; they differ only in how it is delivered:

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

`decbench site build` (CLI in `cli.py`) takes a RESULTS TREE, not a
scoreboard — `scoreboard.toml` is also accepted and resolved to its parent —
and REQUIRES `function_results.json`, since the site is entirely data-driven
(`decbench report` can still fall back to scoreboard-only tables). `data/`
and `fonts/` are wiped per build: stale JSON on a live site is worse than
missing JSON, because nothing reports it. Emits `.nojekyll` (Jekyll silently
drops `_`-prefixed paths).

**Linkable URLs**: the build also writes a `site/<view>/index.html` per
visible view (asset links prefixed `../` directly — deliberately NO
`<base href>`, which would break same-document SVG `url(#marker)` refs and
`#anchors` — plus the `window.__DECBENCH_ROOT__` stamp; stale view dirs are
pruned only when their index.html carries `SITE_PAGE_MARKER`), so
`/leaderboard/` etc. deep-link; client state lives in query params
(`?dataset=<preset>&norm=1`, and on the view page
`?tier=&dec=&metric=&fn=<proj>/<opt>/<bin>::<func>`); legacy `#<view>` hashes
still route.

Payload writers use `json.dumps(..., allow_nan=False)` — browsers parse JSON
strictly, and `function_results.json` CAN contain `ged: Infinity` (non-finite
sample values are dropped by `aggregate._finite_sample`; anything else
non-finite fails the build loudly instead of shipping a payload `JSON.parse`
rejects).

**`.github/workflows/pages.yml` is deploy-ONLY** — CI CANNOT generate the
site (needs the decompilers + ~1.9 GB Joern + ~15 GB of binaries); the
maintainer builds locally and commits `site/` (no longer gitignored), and the
workflow only uploads it, failing if `site/index.html` or
`site/data/aggregates.json` is missing. The workflow triggers on pushes to
`main` that touch `site/**`.

**Republishing after results change** (new runs, new decompiler columns,
score updates — anything that touches `scoreboard.toml` /
`function_results.json`; remember the overlays → finalize flow in
benchmarking.md runs FIRST) is three steps:

```bash
decbench site build results/full_run -o site/      # 1. build locally
git add site && git commit -m 'site: refresh'      # 2. commit it (site/ is deliberately NOT gitignored)
git push                                           # 3. Actions deploys it
```

Before pushing, sanity-check the fresh build against the live site: nothing
extreme should change — e.g. a decompiler losing half its decompiled
functions, or a drastic rank flip — unless a MAJOR benchmark change (new
metric, many projects added/removed) explains it. See the critical rules in
`docs/agents.md`.

---

# The site data schema

The site is a static SPA whose every aggregate view is **precomputed
server-side**. Nothing per-function is shipped except the bounded,
code-carrying `samples` list. Everything below is the normative contract the
build (`site.py`, its only writer) and the client (`app.js`) implement
against.

Every aggregate the report renders is a pure function of two selectors — the
**dataset preset** (`unoptimized` / `optimized` / `inlined` / `large` /
`sample-set`) and the **normalize-failures** toggle — so all `5 x 2 = 10`
combinations are computed once, at build time (rationale and measurements:
"Why precompute" above). Consequence: adding a *new* client-side filter
dimension requires a re-render (`decbench site build`), not just a page
reload. That is the deliberate trade.

## Layout

```
site/
├── index.html          # shell: skeleton + prose, no data (opens on the default view)
├── app.css
├── app.js
├── .nojekyll           # stop Pages from running Jekyll over the tree
├── leaderboard/index.html  # one subpage per VISIBLE view: the same skeleton, that
├── view/index.html         #   view marked active and its asset links prefixed with
├── changelog/index.html    #   "../" (no <base> — that would break same-document SVG
├── about/index.html        #   url(#marker) refs and #anchors). Makes /leaderboard/,
│                           #   /data/, ... directly linkable and reload-safe.
│                           #   (changelog is a prose-only view.)
├── distance/index.html     # MARKER-LESS redirect stub: the distance view became
│                           #   the data view (2026-07-23), and old /distance/
│                           #   links canonicalize + hop to ../data/ preserving
│                           #   ?query#hash. No page marker on purpose — the
│                           #   stale-view prune must keep it (see below).
├── CNAME                   # custom domain (from site.toml [pages].domain)
├── favicon.png             # 64x64 tab icon      \ vendored under
├── apple-touch-icon.png    # 180x180 iOS icon    | assets/icons/, derived
├── decbench_card.png       # 1200x630 OG/Twitter share image  / from decbench_icon.png
├── fonts/                  # vendored Source Code Pro woff2 (offline render)
└── data/
    ├── index.html      # the DATA view's subpage — the `data` view id shares its
    │                   #   directory with the payloads below (deliberate; the
    │                   #   payload wipe runs first, the subpage is written after)
    ├── aggregates.json # the 10 combos + registry + the global cost block. Eager.
    ├── dataset.json    # About page tables + the data page's pipeline-health
    │                   #   section. Corpus-wide, selector-independent.
    └── samples.json    # View page. Lazy — fetched on first view.
```

Every generated page carries the comment marker `<!-- decbench:page -->`. On rebuild
the writer prunes a subdirectory left by a removed/renamed view, but **only** when its
`index.html` carries that marker — never an arbitrary directory (a `CNAME` folder, a
hand-added page) a maintainer dropped in `site/`. The `distance/index.html` redirect
stub is deliberately marker-less so that prune keeps it (`site.py`'s
`_LEGACY_REDIRECTS`); legacy `#distance` hashes are likewise routed client-side
(`app.js`'s `LEGACY_HASH_VIEWS`). `data/` and `fonts/` are wholly regenerated and
wiped first.

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
(so `build_site` computes payloads first, then pages): the leaderboard/data-page text
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

  // GLOBAL, not per-combo (cost doesn't vary by preset/normalize) — see "Cost block".
  "cost": {
    "ghidra": {"time": {"mean_s": 0.21, "median_s": 0.19, "n_functions": 88000,
                        "n_binaries": 790, "basis": "batch"}, "dollars": null},
    "claude-code": {"time": {"mean_s": 240.1, "median_s": 197.0, "n_functions": 250,
                             "basis": "per-function"},
                    "dollars": {"total": 118.40, "per_function": 0.47,
                                "model": "claude-opus-4-8", "estimated": true}}
  },

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
      "compile": {"angr": [890, 1000]},  // Compiles rate (data page): decompiler -> [compiled, byte_match-measured]
      "metric_evidence": {                // sparse measurement provenance; counts only
        "angr": {                         // finite values produced by this decompiler
          "type_match": {"native": 80, "mixed": 8,
                         "fallback_only": 2, "measured": 93}
        }
      },
      "producer_variable_occurrence_policy": { // sparse TypeMatch producer policy counts
        "angr": {"exact": 70, "direct": 10, "unavailable": 8, "undeclared": 2}
      },
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

`metric_evidence` is additive and sparse. For `type_match`, `native` means native
line/address provenance and deterministic anchors were sufficient; `mixed` means
type-blind usage evidence was used jointly with native address/anchor evidence; and
`fallback_only` means type-blind usage evidence was used alone. `measured` counts this
decompiler's finite values in the active combo. It is deliberately not the shared
`per_metric` denominator, which can also include a decompiler's missing value as a
miss. Older `function_results.json` files carry no evidence metadata, so the three
categories may sum to less than `measured`; the client never guesses a category from
a decompiler's name. A measured TypeMatch row still contributes to `measured` when
correspondence accepted no pair and therefore emitted no evidence category.

`producer_variable_occurrence_policy` is also additive and sparse. Its
`exact` / `direct` / `unavailable` / `undeclared` counts cover finite TypeMatch rows
whose producer policy was persisted in `FunctionRecord`. Older `function_results.json`
files omit that field and remain loadable; the aggregate then omits their unknown policy
instead of guessing it.

The leaderboard adds an asterisk to a Type percentage when its active combo has at
least one `mixed` or `fallback_only` measurement, or at least one `unavailable` or
`undeclared` producer policy. Policy is counted independently of accepted-match evidence,
so the marker also covers a measured row where correspondence accepted no pair and
`variable_match_evidence` is absent. The marker is explanatory only: sorting,
percentages, denominators, and Union still read the existing count pairs.

`distance[dec][metric]` is `null` when no function under the combo had a finite
distance for that metric.

### Decompiler registry

`decompiler_registry` maps each decompiler id to how it is shown — `display_name`,
an optional `url` (a project homepage; the client renders a link when present,
`target=_blank rel=noopener`), an optional prettified `version`, an optional
`license` (`"open-source"` / `"closed-source"`), and an optional `logo` flag. The
client (`app.js`'s `decName`/`decUrl`/`decVersion`/`decHasLogo`) renders
these in place of raw ids in the leaderboard, the metrics table, the data page's
distance/compile/cost tables, and the view page's decompiler dropdown; name-sorting sorts
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

### Cost block

The top-level `cost` map (decompiler id → entry) feeds the data page's `#cost` table.
It is **global, not per-combo**: decompile time and dollars do not vary with the
dataset preset or the normalize toggle, so it ships once and `app.js`'s `buildCost`
renders it once at init, outside `refresh()`.

Provenance is a two-layer split so a price fix never needs a re-scan:

* **Facts** live in `FunctionData.cost_info`, written by
  `scripts/compute_cost_info.py` via `decbench/scoring/cost.py` — batch decompile
  times from the results tree's `decompiled/*.toml` headers (`basis: "batch"`,
  per-function time = binary wall time / function count), and per-function LLM
  times + token sums from the structured `FunctionDecompilation.time_seconds` /
  `llm_tokens` fields (new runs) or the `$DECBENCH_LLM_TRACE_DIR` trace scan
  (historical runs). Facts only — no dollar amounts are stored.
* **Prices** live in `decbench/rendering/content/pricing.toml` (USD per MTok per
  model) and are applied at RENDER time (`aggregate._cost_block`).

Entry semantics:

* `time.basis` is `"batch"` (traditional decompilers — an amortized rate) or
  `"per-function"` (LLM agents — one timed agent call per function, tool use
  included). The two are **not directly comparable**; the client renders them in
  separate table halves.
* `dollars` is always `null` for batch entries (no per-token cost). For LLM entries
  it is `{"total", "per_function", "model", "estimated": true}` — an **estimate**
  from recorded token usage at list prices — or `null` when the model is unknown,
  unpriced (pricing.toml ships all-zero **placeholder** cards until the maintainer
  verifies list prices; an unpriced model must render as n/a, never $0.00), or no
  token data was captured.
* Keyed off the visible `decompilers` list, so a site-hidden backend's cost never
  ships; a decompiler with no cost facts is simply absent.

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
  own `#compile-table` in the **data** page's `#compiles` section (it used to be
  a leaderboard column); the combo key is unchanged.
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
