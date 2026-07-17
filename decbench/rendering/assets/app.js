/*
 * DecBench report — the client half of the site.
 *
 * Every aggregate this page renders is PRECOMPUTED server-side. The dataset
 * selector and the "normalize failures" toggle are the only two selectors, so
 * their 5x2 combinations are computed once at build time into
 * data/aggregates.json and looked up here by key ("<preset>|<0|1>"). This file
 * therefore does no aggregation: it renders what it is handed.
 *
 * The fairness rules that decide those numbers — what makes a metric measurable,
 * which functions land in a decompiler's denominator, what Union (the summary
 * column, still keyed `overall` in the payload) and normalize restrict to — are
 * the benchmark's contract and now live server-side. They are
 * specified in docs/SITE_DATA_SCHEMA.md ("Denominator semantics"); do not infer
 * them from this file, which can no longer enforce them.
 *
 * Two delivery modes, one code path (see loadData):
 *
 *   split   a Pages tree. data/aggregates.json is fetched eagerly; the
 *           code-carrying payloads (samples/history) and dataset.json are
 *           fetched on first navigation to their view.
 *   inline  a single-file `decbench report`, opened over file:// where fetch()
 *           is CORS-blocked. The renderer sets window.__DECBENCH_INLINE__ to a
 *           map keyed by data-file stem — {aggregates, dataset, samples,
 *           history} — and we read it directly, never fetching.
 */

// The inline payload, or null in split mode. Set before this script runs.
const INLINE = (typeof window !== "undefined" && window.__DECBENCH_INLINE__) || null;

let AGG = null;
const state = {
    dataset: null,
    view: null,
    sortKey: "__overall__",
    sortDir: -1,
    normalize: false
};

// ---- Data loading ----
// One promise per payload, cached: a view is never fetched twice, and a failure
// stays failed rather than re-storming the network on every navigation.
const _payloads = {};
function loadData(name) {
    if (_payloads[name]) return _payloads[name];
    let p;
    if (INLINE) {
        p = (name in INLINE)
            ? Promise.resolve(INLINE[name])
            : Promise.reject(new Error("inline payload '" + name + "' is missing"));
    } else {
        p = fetch("data/" + name + ".json").then(r => {
            if (!r.ok) throw new Error("HTTP " + r.status + " " + r.statusText);
            return r.json();
        });
    }
    _payloads[name] = p;
    return p;
}

// ---- Metric presentation (from the registry in aggregates.json) ----
// Names and column order used to be hardcoded here AND in html.py; both now read
// decbench/rendering/content/metrics.toml, which ships into aggregates.json.
let _metricSpecs = null;
function metricSpecs() {
    if (_metricSpecs) return _metricSpecs;
    _metricSpecs = {};
    const raw = (AGG && (AGG.metric_registry || AGG.metrics_registry)) || {};
    if (Array.isArray(raw)) {
        raw.forEach(s => { if (s && s.name) _metricSpecs[s.name] = s; });
    } else {
        for (const k in raw) _metricSpecs[k] = Object.assign({name: k}, raw[k]);
    }
    return _metricSpecs;
}
function metricList() { return (AGG && AGG.metrics) || []; }
function metricShort(m) { const s = metricSpecs()[m]; return (s && s.short_name) || m; }
function metricName(m) { const s = metricSpecs()[m]; return (s && s.display_name) || m; }
// Registry order (structure -> types -> recompile); unregistered metrics keep
// their given order and are appended. Mirrors Content.ordered_metrics().
function orderedMetrics() {
    const specs = metricSpecs(), ms = metricList();
    const known = ms.filter(m => m in specs).sort((a, b) => specs[a].order - specs[b].order);
    const extra = ms.filter(m => !(m in specs));
    return known.concat(extra);
}

// ---- Combo lookup (replaces the old client-side recompute) ----
// A run with no dataset presets has no preset to select, so state.dataset stays null.
// The builder emits one synthetic all-functions combo under this reserved name for
// exactly that case (aggregate.py's ALL_PRESET); selecting it renders the full corpus
// with no dataset selector, as the pre-aggregation client's `if (!state.dataset)
// return true;` did. Without the fallback every view here shows an error banner.
const FALLBACK_PRESET = "__all__";
function currentCombo() {
    if (!AGG) return null;
    const ds = state.dataset || FALLBACK_PRESET;
    return (AGG.combos || {})[ds + "|" + (state.normalize ? "1" : "0")] || null;
}
function totalFunctions() { return (AGG && AGG.totals && AGG.totals.functions) || 0; }

// Aggregates ship [numerator, denominator] pairs rather than percentages: the UI
// shows the raw counts next to the bar, so the pair is what it needs.
function pairOf(map, key) { const c = map && map[key]; return c || [0, 0]; }
function metricCell(result, d, m) { return pairOf((result.per_metric || {})[d], m); }
function overallCell(result, d) { return pairOf(result.overall, d); }
function errorCell(result, d) { return pairOf(result.errors, d); }

// ---- Formatting ----
function pctClass(p) { return p >= 50 ? "high" : (p >= 20 ? "mid" : "low"); }
function asciiBar(pct, width) {
    width = width || 12;
    let p = Math.max(0, Math.min(pct, 100));
    let filled = Math.round((p / 100) * width);
    filled = Math.max(0, Math.min(filled, width));
    return "[" + "#".repeat(filled) + "-".repeat(width - filled) + "]";
}
function escapeHtml(s) {
    return (s == null ? "" : String(s))
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function pct(cell) { return cell && cell[1] > 0 ? (cell[0] / cell[1]) * 100 : 0; }

// Read a theme color from CSS (app.css :root owns the palette).
function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
}

// ---- Loading / error states ----
function setLoading(el) { if (el) el.innerHTML = '<p class="view-desc">loading&hellip;</p>'; }
// A failed payload must say so where the reader is looking — never a blank view.
function showBanner(viewId, msg) {
    const sec = document.getElementById("view-" + viewId);
    if (!sec) return;
    let b = sec.querySelector(".banner");
    if (!b) {
        b = document.createElement("div");
        b.className = "banner";
        sec.insertBefore(b, sec.firstChild);
    }
    b.textContent = "[ error ] " + msg;
}

// ---- Leaderboard (swebench-style sortable table) ----
function cellPctHtml(cell) {
    const p = pct(cell);
    return '<span class="bar-ascii">' + asciiBar(p, 8) + '</span> ' +
        '<span class="cell-pct pct-' + pctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
        '<span class="cell-count">(' + cell[0] + '/' + cell[1] + ')</span>';
}
// Errors: lower is better, so the color scale is inverted vs metrics.
function errPctClass(p) { return p < 2 ? "high" : (p < 10 ? "mid" : "low"); }
// Same arithmetic as pct() now that errors ship as an [errored, scope] pair (the
// old pair read .errored/.scope vs .perfect/.total). Kept as its own name so the
// call sites say which rate they mean.
function errRate(cell) { return cell && cell[1] > 0 ? (cell[0] / cell[1]) * 100 : 0; }
function errorCellHtml(cell) {
    const p = errRate(cell);
    return '<span class="cell-pct pct-' + errPctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
        '<span class="cell-count">(' + cell[0] + '/' + cell[1] + ')</span>';
}
function sortValue(d, key, result) {
    if (key === "__name__") return d;
    if (key === "__errors__") return errRate(errorCell(result, d));
    const cell = key === "__overall__" ? overallCell(result, d) : metricCell(result, d, key);
    return pct(cell);
}
function buildLeaderboard(result) {
    const tbl = document.getElementById("leaderboard-table");
    if (!tbl) return;
    const decs = AGG.decompilers.slice(), metrics = orderedMetrics();
    // Header. "Errors" = how often the decompiler failed/timed out on a
    // function it was asked to decompile (lower is better).
    const cols = [["__name__", "decompiler"], ["__overall__", "Union"]];
    for (const m of metrics) cols.push([m, metricShort(m)]);
    cols.push(["__errors__", "Errors"]);
    let head = "<th>#</th>";
    for (const [key, label] of cols) {
        const arrow = state.sortKey === key ? (state.sortDir < 0 ? " ▼" : " ▲") : "";
        const cls = "sortable" + (key === "__overall__" ? " col-overall" : "");
        head += '<th class="' + cls + '" data-sort="' + key + '">' +
            escapeHtml(label) + '<span class="arrow">' + arrow + '</span></th>';
    }
    tbl.querySelector("thead tr").innerHTML = head;
    // Sort.
    decs.sort((a, b) => {
        let va = sortValue(a, state.sortKey, result), vb = sortValue(b, state.sortKey, result);
        if (typeof va === "string") return state.sortDir * va.localeCompare(vb);
        return state.sortDir * (va - vb);
    });
    // Rows.
    let body = "";
    decs.forEach((d, i) => {
        const ver = AGG.decompiler_versions && AGG.decompiler_versions[d];
        const tip = ver ? (d + " — version " + ver) : d;
        let row = '<tr class="binrow"><td class="lb-rank">#' + (i + 1) + '</td>' +
            '<td class="lb-name" title="' + escapeHtml(tip) + '">' + escapeHtml(d) + '</td>';
        row += '<td class="metric-cell col-overall">' + cellPctHtml(overallCell(result, d)) + '</td>';
        for (const m of metrics) row += '<td class="metric-cell">' + cellPctHtml(metricCell(result, d, m)) + '</td>';
        row += '<td class="metric-cell">' + errorCellHtml(errorCell(result, d)) + '</td>';
        row += '</tr>';
        body += row;
    });
    tbl.querySelector("tbody").innerHTML = body;
    tbl.querySelectorAll("th.sortable").forEach(th => {
        th.addEventListener("click", () => {
            const key = th.getAttribute("data-sort");
            if (state.sortKey === key) state.sortDir *= -1;
            else { state.sortKey = key; state.sortDir = (key === "__name__") ? 1 : -1; }
            buildLeaderboard(lastResult);
        });
    });
}

// ---- Metrics perfect-rate table ----
function buildMetricsTable(result) {
    const tbl = document.getElementById("metrics-perfect-table");
    if (!tbl) return;
    const decs = AGG.decompilers, metrics = orderedMetrics();
    let head = "<th>decompiler</th>";
    for (const m of metrics) head += "<th>" + escapeHtml(metricShort(m)) + "</th>";
    head += '<th class="col-overall">Union</th><th>Errors</th>';
    tbl.querySelector("thead tr").innerHTML = head;
    let body = "";
    for (const d of decs) {
        const ver = AGG.decompiler_versions && AGG.decompiler_versions[d];
        const tip = ver ? (d + " — version " + ver) : d;
        let row = '<tr><td class="lb-name" title="' + escapeHtml(tip) + '">' + escapeHtml(d) + '</td>';
        for (const m of metrics) row += '<td class="metric-cell">' + cellPctHtml(metricCell(result, d, m)) + '</td>';
        row += '<td class="metric-cell col-overall">' + cellPctHtml(overallCell(result, d)) + '</td>';
        row += '<td class="metric-cell">' + errorCellHtml(errorCell(result, d)) + '</td>';
        row += '</tr>';
        body += row;
    }
    tbl.querySelector("tbody").innerHTML = body;
}

// ---- Distance view (raw edit distance per metric; lower is better) ----
// mean/median/n/at0 are precomputed per combo; see SITE_DATA_SCHEMA.md. A null
// cell means no function under this combo had a finite distance for that metric.
function buildDistance(result) {
    const tbl = document.getElementById("distance-table");
    if (!tbl) return;
    const decs = AGG.decompilers, metrics = orderedMetrics(), dist = result.distance || {};
    let head = "<th>decompiler</th>";
    for (const m of metrics) head += "<th>" + escapeHtml(metricShort(m)) + " dist</th>";
    tbl.querySelector("thead tr").innerHTML = head;
    // Best (lowest) mean per metric -> highlight; sort rows by mean GED.
    const rows = decs.map(d => ({d, cells: metrics.map(m => (dist[d] && dist[d][m]) || null)}));
    const best = {};
    metrics.forEach((m, i) => {
        best[m] = Math.min.apply(null, rows.map(r => r.cells[i] ? r.cells[i].mean : Infinity));
    });
    rows.sort((a, b) => {
        const av = a.cells[0] ? a.cells[0].mean : Infinity;
        const bv = b.cells[0] ? b.cells[0].mean : Infinity;
        return av - bv;
    });
    let body = "";
    for (const r of rows) {
        let row = '<tr class="binrow"><td class="lb-name">' + escapeHtml(r.d) + '</td>';
        r.cells.forEach((st, i) => {
            if (!st) { row += '<td class="metric-cell">&mdash;</td>'; return; }
            const isBest = st.mean <= best[metrics[i]] + 1e-9;
            row += '<td class="metric-cell">' +
                '<span class="cell-pct ' + (isBest ? 'pct-high' : '') + '">' +
                st.mean.toFixed(1) + '</span> ' +
                '<span class="cell-count">med ' + st.median + ' &middot; ' +
                st.at0 + '/' + st.n + ' at 0</span></td>';
        });
        row += '</tr>';
        body += row;
    }
    tbl.querySelector("tbody").innerHTML = body;
}

function updateStats(result) {
    const fnEl = document.querySelector('[data-stat="functions"]');
    if (fnEl) fnEl.textContent = result.functions.toLocaleString();
    const binEl = document.querySelector('[data-stat="binaries"]');
    if (binEl) binEl.textContent = result.binaries.toLocaleString();
    const counter = document.getElementById("function-counter");
    if (counter) {
        const ds = state.dataset ? ("[" + state.dataset + "] ") : "";
        counter.textContent = ds + result.functions + " / " + totalFunctions() + " fns";
    }
}

let lastResult = null;
function refresh() {
    lastResult = currentCombo();
    if (!lastResult) {
        ["leaderboard", "about", "distance"].forEach(v => showBanner(v,
            "no precomputed aggregates for dataset '" + (state.dataset || FALLBACK_PRESET) +
            "' with normalize=" + (state.normalize ? "on" : "off") + "."));
        return;
    }
    buildLeaderboard(lastResult);
    buildMetricsTable(lastResult);
    buildDistance(lastResult);
    updateStats(lastResult);
}

// ---- About page's dataset section (corpus-wide; independent of the selectors) ----
function buildDataset(ds) {
    const cats = ds.categories || [], summary = ds.summary || {}, joern = ds.joern || {};
    const proj = (ds.projects || []).slice();
    // Category highlight buttons.
    const cc = document.getElementById("category-controls");
    if (cc) {
        cc.innerHTML = cats.map(c =>
            '<button class="ds-btn cat-btn" data-cat="' + escapeHtml(c.name) + '">' +
            escapeHtml(c.name) + ' (' + c.count + ')</button>'
        ).join("");
        cc.querySelectorAll(".cat-btn").forEach(b => b.addEventListener("click", () => {
            const cat = b.getAttribute("data-cat");
            const turnOn = !b.classList.contains("active");
            cc.querySelectorAll(".cat-btn").forEach(x => x.classList.remove("active"));
            document.querySelectorAll("#dataset-projects tbody tr")
                .forEach(tr => tr.classList.remove("cat-hl"));
            if (turnOn) {
                b.classList.add("active");
                document.querySelectorAll('#dataset-projects tbody tr[data-cats~="' + cat + '"]')
                    .forEach(tr => tr.classList.add("cat-hl"));
            }
        }));
    }
    // Summary.
    const sum = document.getElementById("dataset-summary");
    if (sum) {
        sum.innerHTML = '<div class="goal-body">' +
            '<div><span class="num" style="color:var(--green)">' + summary.projects +
            '</span> projects &middot; <strong>' + (summary.unique_binaries || 0).toLocaleString() +
            '</strong> unique binaries &middot; <strong>' + (summary.builds || 0).toLocaleString() +
            '</strong> builds (across opt levels) &middot; <strong>' + (summary.functions || 0).toLocaleString() +
            '</strong> function instances</div>' +
            '<div><strong>' + (summary.total_loc || 0).toLocaleString() +
            '</strong> total source lines of code (project .c files)</div>' +
            '</div>';
    }
    // Pipeline health: source-side GED loss. A benchmark function has NO source
    // CFG iff no decompiler ever got a GED value for it (source CFGs are
    // decompiler-independent), so this is the share of functions GED cannot score
    // because OUR source front-end (Joern) failed or was too slow on the source.
    const src = joern.source || {}, spot = joern.spot_check || {};
    const srcTotal = src.total || 0, srcLost = src.lost || 0;
    const srcPct = srcTotal ? (100 * srcLost / srcTotal) : 0;
    const js = document.getElementById("joern-source");
    if (js) {
        js.innerHTML = '<div class="goal-body"><div class="perfect">' +
            'No source CFG (GED unmeasurable — our source front-end failed/timed out): ' +
            '<strong>' + srcPct.toFixed(1) + '%</strong> of benchmark functions (' +
            srcLost.toLocaleString() + '/' + srcTotal.toLocaleString() +
            '). These are excluded from GED for every decompiler.</div>' +
            (spot.files_sampled ? ('<div class="view-desc" style="margin-top:0.3rem;">' +
                'Direct re-parse spot-check: ' + spot.files_failed + '/' + spot.files_sampled +
                ' sampled source files outright failed' +
                (spot.files_timed_out ? (' (' + spot.files_timed_out +
                ' more too slow to finish — the dominant real-world failure mode)') : '') +
                '.</div>') : '') +
            '</div>';
    }
    // Pipeline health: Joern failures on each decompiler's OUTPUT (corpus-wide).
    const out = joern.output || {};
    const jt = document.getElementById("joern-output-table");
    if (jt) {
        jt.querySelector("thead tr").innerHTML =
            "<th>decompiler</th><th>Joern failed on output</th>";
        jt.querySelector("tbody").innerHTML = Object.keys(out).sort((a, b) =>
            errRate(out[a]) - errRate(out[b])
        ).map(d => {
            const s = out[d], p = errRate(s);
            return '<tr><td class="lb-name">' + escapeHtml(d) + '</td>' +
                '<td class="metric-cell"><span class="cell-pct pct-' + errPctClass(p) + '">' +
                p.toFixed(1) + '%</span> <span class="cell-count">(' + s[0] + '/' +
                s[1] + ')</span></td></tr>';
        }).join("");
    }
    // Projects table (sorted by LOC desc).
    const tbl = document.getElementById("dataset-projects");
    if (tbl) {
        tbl.querySelector("thead tr").innerHTML =
            "<th>project</th><th>types</th><th>LOC</th><th>binaries</th><th>functions</th>";
        tbl.querySelector("tbody").innerHTML = proj.sort((a, b) => b.loc - a.loc).map(p => {
            const pcats = p.cats || [];
            return '<tr data-cats="' + escapeHtml(pcats.join(" ")) + '">' +
                '<td class="lb-name">' + escapeHtml(p.name) + '</td>' +
                '<td class="cell-count">' + (escapeHtml(pcats.join(", ")) || "—") + '</td>' +
                '<td>' + (p.loc ? p.loc.toLocaleString() : "—") + '</td>' +
                '<td>' + p.binaries + '</td>' +
                '<td>' + p.functions.toLocaleString() + '</td></tr>';
        }).join("");
    }
}

// ---- View page (source vs one decompiler, by difficulty tier) ----
// Replaced the old Compare and Hardest views. samples.json entries carry a
// `difficulty` tag (easy/medium/hard, assigned server-side from cross-decompiler
// GED agreement); the three dropdowns pick the tier, the decompiler whose output
// is shown, and the metric whose score is highlighted.
let VIEW_SAMPLES = [];
const DIFFICULTIES = ["easy", "medium", "hard"];
function sampleLabel(s) {
    return s.project + "/" + s.opt_level + "/" + s.binary + " :: " + s.function;
}
function viewControls() {
    return {
        tier: document.getElementById("view-difficulty"),
        dec: document.getElementById("view-dec"),
        metric: document.getElementById("view-metric"),
        fn: document.getElementById("view-select"),
        filter: document.getElementById("view-filter"),
        counter: document.getElementById("view-counter"),
        body: document.getElementById("view-body")
    };
}
function renderViewEntry() {
    const c = viewControls();
    if (!c.fn || !c.body) return;
    const s = VIEW_SAMPLES[parseInt(c.fn.value, 10)];
    if (!s) { c.body.innerHTML = '<p class="view-desc">no function selected.</p>'; return; }
    const dec = c.dec ? c.dec.value : "";
    const selMetric = c.metric ? c.metric.value : "";
    let html = '<div class="cmp-meta">' + escapeHtml(s.project) + '/' +
        escapeHtml(s.opt_level) + '/' + escapeHtml(s.binary) +
        ' &middot; ' + escapeHtml(s.function) +
        (s.size != null ? (' &middot; ' + s.size + ' lines') : '') +
        (s.difficulty ? (' &middot; <span class="tag score-bad">' +
            escapeHtml(s.difficulty) + '</span>') : '') +
        '</div>';
    // Scores strip: the chosen decompiler's per-metric values, chosen metric first.
    const vals = (s.values && s.values[dec]) || {};
    const perf = (s.perfects && s.perfects[dec]) || {};
    let scores = "";
    const ms = orderedMetrics().slice();
    ms.sort((a, b) => (a === selMetric ? -1 : 0) - (b === selMetric ? -1 : 0));
    for (const m of ms) {
        if (!(m in vals)) continue;
        const ok = perf[m] ? "pct-high" : "pct-low";
        const strong = m === selMetric;
        scores += '<span class="sc ' + ok + '"' +
            (strong ? ' style="font-weight:700;text-decoration:underline;"' : '') + '>' +
            metricShort(m) + ' ' + Number(vals[m]).toFixed(2) + '</span>';
    }
    html += '<div class="cmp-scores">' + escapeHtml(dec) + ': ' + (scores || '&mdash;') + '</div>';
    const code = (s.decompiled || {})[dec];
    const cols = (s.source_code ? 1 : 0) + 1;
    html += '<div class="cmp-grid" style="grid-template-columns:repeat(' +
        Math.max(1, cols) + ',minmax(0,1fr));">';
    if (s.source_code) {
        html += '<div class="cmp-col src"><h4>source (ground truth)</h4>' +
            '<pre><code>' + escapeHtml(s.source_code) + '</code></pre></div>';
    }
    html += '<div class="cmp-col"><h4>' + escapeHtml(dec) + '</h4>' +
        (code ? ('<pre><code>' + escapeHtml(code) + '</code></pre>')
              : ('<p class="view-desc">no output from ' + escapeHtml(dec) +
                 ' for this function.</p>')) +
        '</div>';
    html += '</div>';
    c.body.innerHTML = html;
}
function fillViewFunctions() {
    const c = viewControls();
    if (!c.fn) return;
    const tier = c.tier ? c.tier.value : "__all__";
    const q = (c.filter && c.filter.value || "").toLowerCase();
    c.fn.innerHTML = "";
    let shown = 0, tierTotal = 0;
    VIEW_SAMPLES.forEach((s, i) => {
        const inTier = tier === "__all__" || (s.difficulty || "__none__") === tier;
        if (!inTier) return;
        tierTotal += 1;
        const label = sampleLabel(s);
        if (q && label.toLowerCase().indexOf(q) < 0) return;
        const o = document.createElement("option");
        o.value = i; o.textContent = label;
        c.fn.appendChild(o); shown += 1;
    });
    if (c.counter) c.counter.textContent = shown + " / " + tierTotal + " functions";
    renderViewEntry();
}
function initView(samples) {
    VIEW_SAMPLES = samples || [];
    const c = viewControls();
    if (!c.fn) return;
    // Difficulty tiers present in the data; legacy payloads (no tags) get "all".
    const tiers = DIFFICULTIES.filter(t => VIEW_SAMPLES.some(s => s.difficulty === t));
    if (c.tier) {
        (tiers.length ? tiers : ["__all__"]).forEach(t => {
            const o = document.createElement("option");
            o.value = t; o.textContent = t === "__all__" ? "all" : t;
            c.tier.appendChild(o);
        });
    }
    // Decompilers: union over the entries (covers versioned ids), sorted.
    const decs = [];
    for (const s of VIEW_SAMPLES) {
        for (const d in (s.decompiled || {})) if (decs.indexOf(d) < 0) decs.push(d);
    }
    decs.sort();
    if (c.dec) {
        decs.forEach(d => {
            const o = document.createElement("option");
            o.value = d; o.textContent = d;
            c.dec.appendChild(o);
        });
    }
    if (c.metric) {
        orderedMetrics().forEach(m => {
            const o = document.createElement("option");
            o.value = m; o.textContent = metricName(m);
            c.metric.appendChild(o);
        });
    }
    if (c.tier) c.tier.addEventListener("change", fillViewFunctions);
    if (c.dec) c.dec.addEventListener("change", renderViewEntry);
    if (c.metric) c.metric.addEventListener("change", renderViewEntry);
    c.fn.addEventListener("change", renderViewEntry);
    if (c.filter) c.filter.addEventListener("input", fillViewFunctions);
    fillViewFunctions();
}

// ---- Historical (SVG) ----
// Series palette. --green/--amber/--red are app.css's; the other seven are
// chart-only series colors with no token to read them from.
let _chartColors = null;
function chartColors() {
    if (!_chartColors) {
        _chartColors = [
            cssVar("--green", "#6ab04c"), "#4a90d9", cssVar("--amber", "#d4a72c"),
            cssVar("--red", "#c0504d"), "#9b59b6", "#1abc9c", "#e67e22", "#7f8c8d",
            "#e84393", "#00cec9"
        ];
    }
    return _chartColors;
}
function baseName(dec) { const a = dec.indexOf("@"); return a >= 0 ? dec.substring(0, a) : dec; }
function svgEl(tag, attrs) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    return el;
}
function buildChart(container, history, metricKey, title) {
    const versions = [];
    for (const h of history) if (versions.indexOf(h.version) < 0) versions.push(h.version);
    const lines = {};
    for (const h of history) {
        const bn = baseName(h.decompiler);
        let val = metricKey === "__overall__" ? h.overall :
            (h.scores && (metricKey in h.scores) ? h.scores[metricKey] : null);
        if (val == null) continue;
        if (!lines[bn]) lines[bn] = {};
        lines[bn][h.version] = val;
    }
    const decNames = Object.keys(lines).sort();
    if (!decNames.length || versions.length < 1) return;
    const block = document.createElement("div");
    block.className = "chart-block";
    const h3 = document.createElement("h3"); h3.textContent = title; block.appendChild(h3);
    const W = 760, H = 280, padL = 46, padR = 16, padT = 14, padB = 40;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const svg = svgEl("svg", {viewBox: "0 0 " + W + " " + H, width: W, height: H, role: "img"});
    const xFor = i => versions.length === 1 ? padL + plotW / 2 : padL + (plotW * i) / (versions.length - 1);
    const yFor = v => padT + plotH - (plotH * Math.max(0, Math.min(v, 100)) / 100);
    // Chart chrome: the muted label color is app.css's; the gridline/axis greys
    // have no token yet, so they read one if it appears and fall back to today's.
    const gridColor = cssVar("--chart-grid", "#333");
    const axisColor = cssVar("--chart-axis", "#666");
    const labelColor = cssVar("--text-muted", "#8a8a8a");
    for (let g = 0; g <= 100; g += 25) {
        const y = yFor(g);
        svg.appendChild(svgEl("line", {x1: padL, y1: y, x2: W - padR, y2: y, stroke: gridColor, "stroke-width": 1, "stroke-dasharray": "3 3"}));
        const lbl = svgEl("text", {x: padL - 6, y: y + 4, "text-anchor": "end", fill: labelColor, "font-size": 11, "font-family": "Source Code Pro, monospace"});
        lbl.textContent = g + "%"; svg.appendChild(lbl);
    }
    svg.appendChild(svgEl("line", {x1: padL, y1: padT, x2: padL, y2: padT + plotH, stroke: axisColor, "stroke-width": 1}));
    svg.appendChild(svgEl("line", {x1: padL, y1: padT + plotH, x2: W - padR, y2: padT + plotH, stroke: axisColor, "stroke-width": 1}));
    for (let i = 0; i < versions.length; i++) {
        const t = svgEl("text", {x: xFor(i), y: padT + plotH + 18, "text-anchor": "middle", fill: labelColor, "font-size": 11, "font-family": "Source Code Pro, monospace"});
        t.textContent = versions[i]; svg.appendChild(t);
    }
    const palette = chartColors();
    const colorByDec = {};
    decNames.forEach((dn, idx) => {
        const color = palette[idx % palette.length];
        colorByDec[dn] = color;
        const pts = [];
        for (let i = 0; i < versions.length; i++) {
            const v = lines[dn][versions[i]];
            if (v == null) continue;
            const x = xFor(i), y = yFor(v);
            pts.push(x + "," + y);
            svg.appendChild(svgEl("circle", {cx: x, cy: y, r: 3, fill: color}));
        }
        if (pts.length >= 2) svg.appendChild(svgEl("polyline", {points: pts.join(" "), fill: "none", stroke: color, "stroke-width": 2}));
    });
    block.appendChild(svg);
    const legend = document.createElement("div"); legend.className = "legend";
    for (const dn of decNames) {
        const span = document.createElement("span"); span.className = "item";
        const sw = document.createElement("span"); sw.className = "swatch"; sw.style.background = colorByDec[dn];
        span.appendChild(sw); span.appendChild(document.createTextNode(dn)); legend.appendChild(span);
    }
    block.appendChild(legend); container.appendChild(block);
}
function initHistory(history) {
    const container = document.getElementById("history-charts");
    if (!container || !(history || []).length) return;
    container.innerHTML = "";
    for (const m of metricList()) buildChart(container, history, m, metricName(m));
    buildChart(container, history, "__overall__", "Union (perfect on at least one metric)");
}

// ---- Lazy views ----
// Fetched on FIRST navigation, once. Each also waits on aggregates, which carry
// the metric registry these views label their columns and scores with.
const LAZY_VIEWS = {
    about: {file: "dataset", body: "dataset-summary", render: buildDataset},
    view: {file: "samples", body: "view-body", render: initView},
    history: {file: "history", body: "history-charts", render: initHistory}
};
const lazyStarted = {};
function ensureViewData(name) {
    const spec = LAZY_VIEWS[name];
    if (!spec || lazyStarted[name]) return;
    const body = document.getElementById(spec.body);
    if (!body) return;  // the view rendered its empty state: nothing to fill.
    lazyStarted[name] = true;
    setLoading(body);
    Promise.all([loadData("aggregates"), loadData(spec.file)])
        .then(([, data]) => spec.render(data))
        .catch(err => {
            body.innerHTML = "";
            showBanner(name, "could not load data/" + spec.file + ".json — " + err.message);
        });
}

// ---- View routing ----
function showView(name) {
    state.view = name;
    document.querySelectorAll(".view").forEach(v => {
        v.classList.toggle("active", v.getAttribute("data-view") === name);
    });
    document.querySelectorAll(".nav-item").forEach(a => {
        a.classList.toggle("active", a.getAttribute("data-view") === name);
    });
    ensureViewData(name);
}
// The view to open when the URL carries no (valid) hash. It is config —
// views.toml's `default = true` — and reaches us through the DOM: the renderer
// marks that section `active`, and routing must run before aggregates.json lands,
// so we cannot wait to read `default_view` out of it. Same value either way.
function defaultView() {
    const el = document.querySelector(".view.active") || document.querySelector(".view");
    return el ? el.getAttribute("data-view") : null;
}
function initNav() {
    document.querySelectorAll(".nav-item").forEach(a => {
        a.addEventListener("click", e => {
            e.preventDefault();
            showView(a.getAttribute("data-view"));
        });
    });
    const initial = (location.hash || "").replace("#", "");
    const valid = Array.from(document.querySelectorAll(".view")).map(v => v.getAttribute("data-view"));
    const target = valid.indexOf(initial) >= 0 ? initial : defaultView();
    if (target) showView(target);
}

function setDatasetDesc() {
    const el = document.getElementById("dataset-desc");
    if (!el) return;
    const p = (AGG.presets || []).filter(x => x.name === state.dataset)[0];
    el.textContent = p ? p.description : "";
}
function initDatasetSelector() {
    const presets = AGG.presets || [];
    // The opening preset is explicit (`default = true` in datasets.toml), never
    // positional; sync the buttons to it so state and UI cannot disagree.
    const def = presets.filter(p => p.default)[0] || presets[0];
    state.dataset = def ? def.name : null;
    // Only the preset buttons carry data-dataset (the normalize toggle does not).
    const btns = document.querySelectorAll(".ds-btn[data-dataset]");
    btns.forEach(b => {
        b.classList.toggle("active", b.getAttribute("data-dataset") === state.dataset);
        b.addEventListener("click", () => {
            state.dataset = b.getAttribute("data-dataset");
            btns.forEach(x => x.classList.remove("active"));
            b.classList.add("active");
            setDatasetDesc();
            refresh();
        });
    });
    setDatasetDesc();
    // "normalize failures": restrict to functions every decompiler decompiled.
    const nb = document.getElementById("normalize-btn");
    if (nb) nb.addEventListener("click", () => {
        state.normalize = !state.normalize;
        nb.classList.toggle("active", state.normalize);
        refresh();
    });
}

function init() {
    initNav();
    loadData("aggregates").then(agg => {
        AGG = agg;
        initDatasetSelector();
        refresh();
    }).catch(err => {
        ["leaderboard", "about", "distance"].forEach(v => showBanner(v,
            "could not load data/aggregates.json — " + err.message +
            ". this view has no data."));
    });
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
