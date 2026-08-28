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
 * specified in docs/site.md ("Denominator semantics"); do not infer
 * them from this file, which can no longer enforce them.
 *
 * Two delivery modes, one code path (see loadData):
 *
 *   split   a Pages tree. data/aggregates.json is fetched eagerly; the
 *           code-carrying samples payload and dataset.json are fetched on first
 *           navigation to their view.
 *   inline  a single-file `decbench report`, opened over file:// where fetch()
 *           is CORS-blocked. The renderer sets window.__DECBENCH_INLINE__ to a
 *           map keyed by data-file stem — {aggregates, dataset, samples} — and
 *           we read it directly, never fetching.
 */

/* ============================================================================
 * Self-contained syntax highlighter — no third-party code, no CDN.
 *
 * An IIFE exposing three globals on `window` (this is a classic script, so they
 * are reachable as bare names below):
 *   hlC(code)                    -> HTML string  (C / decompiler pseudo-C)
 *   hlAsm(text)                  -> HTML string  (x86-64 Intel + basic ARM)
 *   applyStaticHighlights(root)  -> highlight every <pre data-lang="c|asm">
 *
 * Token span classes are styled in app.css (tok-kw, tok-type, ...). The
 * tokenizers escape every token and clamp unterminated strings/comments to
 * EOL/EOF, so the output is well-formed on adversarial input.
 * ==========================================================================*/
(function (global) {
  "use strict";

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  function span(cls, text) {
    return '<span class="' + cls + '">' + esc(text) + "</span>";
  }

  var C_KEYWORDS = new Set([
    "if", "else", "for", "while", "do", "switch", "case", "default", "break",
    "continue", "return", "goto", "sizeof", "typedef", "struct", "union",
    "enum", "static", "const", "volatile", "register", "extern", "inline",
    "restrict", "auto", "signed", "unsigned", "_Bool", "_Complex", "_Noreturn",
    "_Static_assert", "_Alignas", "_Alignof", "_Generic", "_Thread_local",
    "asm", "__asm__", "__attribute__", "__restrict", "__inline",
    "__volatile__", "__extension__", "true", "false", "NULL"
  ]);
  var C_TYPES = new Set([
    "void", "char", "short", "int", "long", "float", "double", "bool",
    "size_t", "ssize_t", "ptrdiff_t", "wchar_t", "va_list", "FILE", "off_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "intptr_t", "uintptr_t",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "uint", "ulong", "ushort", "uchar", "byte", "word", "dword", "qword",
    "code", "__int8", "__int16", "__int32", "__int64", "__uint64",
    "_BOOL1", "_BOOL2", "_BOOL4", "_BOOL8",
    "_BYTE", "_WORD", "_DWORD", "_QWORD", "_UNKNOWN",
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "bool_t"
  ]);

  function isIdentStart(c) {
    return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_" || c === "$";
  }
  function isIdentChar(c) {
    return isIdentStart(c) || (c >= "0" && c <= "9");
  }
  function isDigit(c) { return c >= "0" && c <= "9"; }
  function isHex(c) {
    return (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
  }
  function isSpaceNoNL(c) { return c === " " || c === "\t" || c === "\r"; }

  function hlC(code) {
    code = String(code == null ? "" : code);
    var out = "", plain = "", i = 0, n = code.length;
    var atLineStart = true;
    function flush() { if (plain) { out += esc(plain); plain = ""; } }

    while (i < n) {
      var c = code[i];

      if (c === "#" && atLineStart) {
        flush();
        var j = i;
        while (j < n && code[j] !== "\n") {
          if (code[j] === "\\" && code[j + 1] === "\n") { j += 2; continue; }
          j++;
        }
        out += span("tok-pp", code.slice(i, j));
        i = j; atLineStart = true; continue;
      }
      if (c === "/" && code[i + 1] === "/") {
        flush();
        var k = code.indexOf("\n", i); if (k < 0) k = n;
        out += span("tok-com", code.slice(i, k));
        i = k; continue;
      }
      if (c === "/" && code[i + 1] === "*") {
        flush();
        var e = code.indexOf("*/", i + 2); e = (e < 0) ? n : e + 2;
        out += span("tok-com", code.slice(i, e));
        i = e; atLineStart = false; continue;
      }
      if (c === '"' || c === "'") {
        flush();
        var q = c, p = i + 1;
        while (p < n) {
          if (code[p] === "\\") { p += 2; continue; }
          if (code[p] === q || code[p] === "\n") break;
          p++;
        }
        if (code[p] === q) p++;
        out += span("tok-str", code.slice(i, p));
        i = p; atLineStart = false; continue;
      }
      if (isDigit(c) || (c === "." && isDigit(code[i + 1]))) {
        flush();
        var s = i;
        if (c === "0" && (code[i + 1] === "x" || code[i + 1] === "X")) {
          i += 2; while (i < n && isHex(code[i])) i++;
        } else {
          while (i < n && isDigit(code[i])) i++;
          if (code[i] === ".") { i++; while (i < n && isDigit(code[i])) i++; }
          if (code[i] === "e" || code[i] === "E") {
            i++; if (code[i] === "+" || code[i] === "-") i++;
            while (i < n && isDigit(code[i])) i++;
          }
        }
        while (i < n && "uUlLfF".indexOf(code[i]) >= 0) i++;
        out += span("tok-num", code.slice(s, i));
        atLineStart = false; continue;
      }
      if (isIdentStart(c)) {
        flush();
        var a = i; i++;
        while (i < n && isIdentChar(code[i])) i++;
        var word = code.slice(a, i);
        if (C_KEYWORDS.has(word)) out += span("tok-kw", word);
        else if (C_TYPES.has(word)) out += span("tok-type", word);
        else {
          var m = i; while (m < n && isSpaceNoNL(code[m])) m++;
          if (code[m] === "(") out += span("tok-call", word);
          else out += esc(word);
        }
        atLineStart = false; continue;
      }
      if (c === "\n") { plain += c; atLineStart = true; i++; continue; }
      if (!isSpaceNoNL(c)) atLineStart = false;
      plain += c; i++;
    }
    flush();
    return out;
  }

  var X86_REGS = new Set([
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
    "sil", "dil", "bpl", "spl",
    "lr", "pc", "fp", "ip", "sb", "sl", "xzr", "wzr"
  ]);
  function isReg(w) {
    var r = w.toLowerCase();
    if (X86_REGS.has(r)) return true;
    if (/^r\d{1,2}[dwb]?$/.test(r)) return true;
    if (/^[xw]([0-9]|[12][0-9]|3[01])$/.test(r)) return true;
    if (/^(xmm|ymm|zmm)\d{1,2}$/.test(r)) return true;
    if (/^[dsq]([0-9]|[12][0-9]|3[01])$/.test(r)) return true;
    return false;
  }

  function readNumTail(line, s) {
    var n = line.length;
    if (line[s] === "+" || line[s] === "-") s++;
    if (line[s] === "0" && (line[s + 1] === "x" || line[s + 1] === "X")) {
      s += 2; while (s < n && isHex(line[s])) s++;
    } else {
      while (s < n && isDigit(line[s])) s++;
    }
    return s;
  }

  function hlAsmLine(line) {
    var n = line.length, i = 0, out = "";
    var ws = 0; while (ws < n && (line[ws] === " " || line[ws] === "\t")) ws++;
    if (ws) { out += esc(line.slice(0, ws)); i = ws; }

    var lm = /^([.\w$@]+):/.exec(line.slice(i));
    if (lm) {
      out += span("tok-lbl", lm[0]);
      i += lm[0].length;
      var w2 = 0;
      while (i + w2 < n && (line[i + w2] === " " || line[i + w2] === "\t")) w2++;
      if (w2) { out += esc(line.slice(i, i + w2)); i += w2; }
    }

    var mnemSeen = false;
    while (i < n) {
      var c = line[i];
      if (c === ";" || c === "@") { out += span("tok-com", line.slice(i)); break; }
      if (c === "/" && line[i + 1] === "/") { out += span("tok-com", line.slice(i)); break; }
      if (c === "#") {
        var d = line[i + 1];
        if (d === "-" || d === "+" || (d >= "0" && d <= "9")) {
          var s = readNumTail(line, i + 1);
          out += span("tok-imm", line.slice(i, s)); i = s; continue;
        }
        out += span("tok-com", line.slice(i)); break;
      }
      if (c === " " || c === "\t") {
        var a = i; while (i < n && (line[i] === " " || line[i] === "\t")) i++;
        out += esc(line.slice(a, i)); continue;
      }
      if (c === "$") {
        var s2 = readNumTail(line, i + 1);
        out += span("tok-imm", line.slice(i, s2)); i = s2; continue;
      }
      if (isDigit(c)) {
        var s3 = i;
        if (c === "0" && (line[i + 1] === "x" || line[i + 1] === "X")) {
          i += 2; while (i < n && isHex(line[i])) i++;
        } else {
          while (i < n && isDigit(line[i])) i++;
        }
        out += span("tok-imm", line.slice(s3, i)); continue;
      }
      if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_" || c === ".") {
        var wstart = i; i++;
        while (i < n && /[\w.$]/.test(line[i])) i++;
        var word = line.slice(wstart, i);
        if (!mnemSeen) {
          mnemSeen = true;
          out += span(word[0] === "." ? "tok-pp" : "tok-mn", word);
        } else if (isReg(word)) {
          out += span("tok-reg", word);
        } else {
          out += esc(word);
        }
        continue;
      }
      out += esc(c); i++;
    }
    return out;
  }

  function hlAsm(text) {
    text = String(text == null ? "" : text);
    return text.split("\n").map(hlAsmLine).join("\n");
  }

  function applyStaticHighlights(root) {
    root = root || (typeof document !== "undefined" ? document : null);
    if (!root) return;
    var pres = root.querySelectorAll("pre[data-lang]");
    for (var i = 0; i < pres.length; i++) {
      var pre = pres[i];
      if (pre.getAttribute("data-hl") === "1") continue;
      var lang = (pre.getAttribute("data-lang") || "").toLowerCase();
      var target = pre.querySelector("code") || pre;
      var text = target.textContent;
      target.innerHTML = (lang === "asm") ? hlAsm(text) : hlC(text);
      pre.setAttribute("data-hl", "1");
    }
  }

  global.hlC = hlC;
  global.hlAsm = hlAsm;
  global.applyStaticHighlights = applyStaticHighlights;
})(typeof window !== "undefined" ? window
  : (typeof globalThis !== "undefined" ? globalThis : this));

const INLINE = (typeof window !== "undefined" && window.__DECBENCH_INLINE__) || null;

const ROOT = (typeof window !== "undefined" && typeof window.__DECBENCH_ROOT__ === "string")
    ? window.__DECBENCH_ROOT__ : null;

const INIT_PARAMS = (function () {
    try { return new URLSearchParams(location.search); } catch (e) { return new URLSearchParams(); }
})();

// ---- Snapshots (?snapshot=DD-MM-YYYY) ----
// Mirrors decbench/rendering/snapshots.py: SNAPSHOT_PAYLOADS is the same set of
// data-file stems a snapshot freezes (samples.json is deliberately not one), and
// the two accepted date forms are the ones parse_date() takes, ISO normalized to
// the canonical DD-MM-YYYY. Validated on this side too: an arbitrary query param
// must never become a fetch path.
const SNAPSHOT_PAYLOADS = {aggregates: 1, dataset: 1};
const SNAPSHOT_RE = /^\d{2}-\d{2}-\d{4}$/;
const SNAPSHOT_ISO_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const SNAPSHOT = (function () {
    const raw = (INIT_PARAMS.get("snapshot") || "").trim();
    if (SNAPSHOT_RE.test(raw)) return raw;
    const iso = SNAPSHOT_ISO_RE.exec(raw);
    return iso ? (iso[3] + "-" + iso[2] + "-" + iso[1]) : null;
})();

// Cached deliberately: pushState later moves location without moving the root,
// so recomputing from a post-navigation URL would lie.
// that first loaded plus the stamped hop. Cached deliberately: pushState later moves
// location without moving the root, so recomputing from a post-navigation URL lies.
let _basePath = null;
function basePath() {
    if (_basePath === null) {
        try { _basePath = new URL(ROOT || "./", location.href).pathname; }
        catch (e) { _basePath = "/"; }
    }
    return _basePath;
}
// Resolve NOW, before any pushState moves location.
// compute the root from wherever the user has since navigated.
if (ROOT !== null) basePath();

let AGG = null;
const state = {
    dataset: null,
    view: null,
    sortKey: "__overall__",
    sortDir: -1,
    normalize: false
};

// The snapshot listing is always live; a frozen payload comes from that day's
// own directory (snapshots.py's write_snapshot_tree lays both out).
function dataPath(name) {
    if (name === "snapshots") return "data/snapshots/index.json";
    if (SNAPSHOT && SNAPSHOT_PAYLOADS[name]) {
        return "data/snapshots/" + SNAPSHOT + "/" + name + ".json";
    }
    return "data/" + name + ".json";
}

const _payloads = {};
function loadData(name) {
    if (_payloads[name]) return _payloads[name];
    let p;
    if (INLINE) {
        p = (name in INLINE)
            ? Promise.resolve(INLINE[name])
            : Promise.reject(new Error("inline payload '" + name + "' is missing"));
    } else {
        // Anchored to the site root, not the document: a relative "data/..." would
// re-resolve after pushState, and the first cached rejection would then stick.
        // re-resolve against whatever path pushState/replaceState moved us to, and
        // the first cached rejection would stick for the whole session.
        const prefix = ROOT !== null ? basePath() : "";
        p = fetch(prefix + dataPath(name)).then(r => {
            if (!r.ok) throw new Error("HTTP " + r.status + " " + r.statusText);
            return r.json();
        });
    }
    _payloads[name] = p;
    return p;
}

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
function orderedMetrics() {
    const specs = metricSpecs(), ms = metricList();
    const known = ms.filter(m => m in specs).sort((a, b) => specs[a].order - specs[b].order);
    const extra = ms.filter(m => !(m in specs));
    return known.concat(extra);
}

// ---- Decompiler presentation (from the registry in aggregates.json) ----
// SHOW_LOGOS is the single switch for the leaderboard logos; flip it to false to
// disable them everywhere with no other edit.
// Official names / links / prettified versions replace raw ids on screen. Tolerant
// the same way metricSpecs is: a missing registry (older payload) or an unknown id
// (r2dec/dewolf data landing before its entry) falls back to the raw id, unlinked.
//
// SHOW_LOGOS is the single switch for the logos: when true, decompilers the
// registry marks with `logo` get a small `.dlogo-<base>` badge prepended to their
// (stacked) leaderboard name. Flip it to false to disable logos everywhere with no
// other edit. ON by maintainer choice (2026-07-20), with the grayscale-at-rest /
// colour-on-row-hover treatment keeping them quiet on the mono page; the license
// tag that briefly lived under the version was dropped at the same time (the
// registry still carries `license` — only the rendering was removed).
const SHOW_LOGOS = true;
function decRegistry() { return (AGG && AGG.decompiler_registry) || {}; }
function decRegEntry(id) {
    const reg = decRegistry();
    if (reg[id]) return reg[id];
    const base = baseName(id);
    if (reg[base]) return reg[base];
    for (const k in reg) if (baseName(k) === base) return reg[k];
    return null;
}
function decName(id) { const e = decRegEntry(id); return (e && e.display_name) || id; }
function decUrl(id) { const e = decRegEntry(id); return (e && e.url) || null; }
function decHasLogo(id) { const e = decRegEntry(id); return !!(e && e.logo); }
function decVersion(id) {
    const e = decRegEntry(id);
    if (e && e.version) return e.version;
    return (AGG && AGG.decompiler_versions && AGG.decompiler_versions[id]) || null;
}
function decTip(id) {
    const v = decVersion(id);
    return v ? (decName(id) + " — version " + v) : decName(id);
}
function decNameHtml(id, options) {
    options = options || {};
    const name = escapeHtml(decName(id)), url = decUrl(id), v = decVersion(id);
    const logo = (SHOW_LOGOS && decHasLogo(id))
        ? '<span class="dlogo dlogo-' + escapeHtml(baseName(id)) + '"></span>'
        : '';
    const nameHtml = url
        ? '<a href="' + escapeHtml(url) + '" target="_blank" rel="noopener">' + name + '</a>'
        : name;
    const vtxt = v ? (/^\d/.test(v) ? "v" + v : v) : null;
    if (!options.stacked) {
        return logo + nameHtml +
            (vtxt ? ' <span class="ver">' + escapeHtml(vtxt) + '</span>' : '');
    }
    let html = '<span class="lb-stack"><span class="lb-nm">' + logo + nameHtml + '</span>';
    if (vtxt) html += '<span class="ver">' + escapeHtml(vtxt) + '</span>';
    return html + '</span>';
}

// ---- Combo lookup ----
// A run with no dataset presets has none to select, so the builder emits one
// synthetic all-functions combo under this reserved name (aggregate.py's
// ALL_PRESET). Without the fallback every view here shows an error banner.
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

function pairOf(map, key) { const c = map && map[key]; return c || [0, 0]; }
function metricCell(result, d, m) { return pairOf((result.per_metric || {})[d], m); }

// Decompilers to render as rows for the CURRENT preset. AGG.sample_set_only
// backends ran on the sample-set slice only, so they render there and, on the
// data page, below a partial-coverage break (splitDecs) — never elsewhere.
// AGG.sample_set_only (the LLM/coding-agent ones — codex/claude-code) ran on the
// sample-set slice only, so their rows are shown ONLY when the sample-set preset is
// selected; on every other view they are omitted (their data still ships, it is
// just not rendered where the shared denominator would make them look near-empty).
// Exception: the data page renders them everywhere via splitDecs() below —
// separated and marked as partial-coverage instead of hidden.
const SAMPLE_SET_PRESET = "sample-set";
function visibleDecs() {
    const all = ((AGG && AGG.decompilers) || []).slice();
    const sso = (AGG && AGG.sample_set_only) || [];
    if (!sso.length) return all;
    const preset = state.dataset || defaultPresetName();
    if (preset === SAMPLE_SET_PRESET) return all;
    return all.filter(d => sso.indexOf(d) < 0);
}
function splitDecs() {
    const all = ((AGG && AGG.decompilers) || []).slice();
    const sso = (AGG && AGG.sample_set_only) || [];
    const preset = state.dataset || defaultPresetName();
    if (!sso.length || preset === SAMPLE_SET_PRESET) return {main: all, subset: []};
    return {
        main: all.filter(d => sso.indexOf(d) < 0),
        subset: all.filter(d => sso.indexOf(d) >= 0),
    };
}
function subsetBreakRow(colspan) {
    return '<tr class="subset-break"><td colspan="' + colspan +
        '">&mdash; sample-set only &mdash;</td></tr>';
}
function toggleSubsetNote(id, on) {
    const el = document.getElementById(id);
    if (el) el.hidden = !on;
}
function overallCell(result, d) { return pairOf(result.overall, d); }
function errorCell(result, d) { return pairOf(result.errors, d); }
function compileCell(result, d) { return pairOf(result.compile, d); }

function pctClass(p) { return p >= 50 ? "high" : (p >= 20 ? "mid" : "low"); }
function asciiBar(pct, width) {
    width = width || 12;
    let p = Math.max(0, Math.min(pct, 100));
    let filled = Math.round((p / 100) * width);
    filled = Math.max(0, Math.min(filled, width));
    return "[" + "#".repeat(filled) + "-".repeat(width - filled) + "]";
}
// Quotes are escaped too: several callers interpolate into an attribute value
// (href=, title=), where a bare " would close it and turn text into markup.
function escapeHtml(s) {
    return (s == null ? "" : String(s))
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function pct(cell) { return cell && cell[1] > 0 ? (cell[0] / cell[1]) * 100 : 0; }

function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
}

function setLoading(el) { if (el) el.innerHTML = '<p class="view-desc">Loading&hellip;</p>'; }
function bannerFor(viewId) {
    const sec = document.getElementById("view-" + viewId);
    if (!sec) return null;
    let b = sec.querySelector(".banner");
    if (!b) {
        b = document.createElement("div");
        b.className = "banner";
        sec.insertBefore(b, sec.firstChild);
    }
    return b;
}
function showBanner(viewId, msg) {
    const b = bannerFor(viewId);
    if (b) b.textContent = "[ error ] " + msg;
}
function showBannerHtml(viewId, html) {
    const b = bannerFor(viewId);
    if (b) b.innerHTML = html;
}

function cellPctHtml(cell) {
    const p = pct(cell);
    return '<span class="bar-ascii">' + asciiBar(p, 8) + '</span> ' +
        '<span class="cell-pct pct-' + pctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
        '<span class="cell-count">(' + cell[0] + '/' + cell[1] + ')</span>';
}
function errPctClass(p) { return p < 2 ? "high" : (p < 10 ? "mid" : "low"); }
function errRate(cell) { return cell && cell[1] > 0 ? (cell[0] / cell[1]) * 100 : 0; }
function errorCellHtml(cell) {
    const p = errRate(cell);
    return '<span class="cell-pct pct-' + errPctClass(p) + '">' + p.toFixed(1) + '%</span> ' +
        '<span class="cell-count">(' + cell[0] + '/' + cell[1] + ')</span>';
}
function sortValue(d, key, result) {
    if (key === "__name__") return decName(d);
    if (key === "__errors__") return errRate(errorCell(result, d));
    const cell = key === "__overall__" ? overallCell(result, d) : metricCell(result, d, key);
    return pct(cell);
}
function buildLeaderboard(result) {
    const tbl = document.getElementById("leaderboard-table");
    if (!tbl) return;
    const decs = visibleDecs(), metrics = orderedMetrics();
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
    decs.sort((a, b) => {
        let va = sortValue(a, state.sortKey, result), vb = sortValue(b, state.sortKey, result);
        if (typeof va === "string") return state.sortDir * va.localeCompare(vb);
        return state.sortDir * (va - vb);
    });
    let body = "";
    decs.forEach((d, i) => {
        let row = '<tr class="binrow"><td class="lb-rank">#' + (i + 1) + '</td>' +
            '<td class="lb-name lb-name-stacked" title="' + escapeHtml(decTip(d)) + '">' +
            decNameHtml(d, {stacked: true}) + '</td>';
        row += '<td class="metric-cell col-overall" data-label="Union">' + cellPctHtml(overallCell(result, d)) + '</td>';
        for (const m of metrics) row += '<td class="metric-cell" data-label="' + escapeHtml(metricShort(m)) + '">' + cellPctHtml(metricCell(result, d, m)) + '</td>';
        row += '<td class="metric-cell" data-label="Errors">' + errorCellHtml(errorCell(result, d)) + '</td>';
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

function buildMetricsTable(result) {
    const tbl = document.getElementById("metrics-perfect-table");
    if (!tbl) return;
    const decs = visibleDecs(), metrics = orderedMetrics();
    let head = "<th>decompiler</th>";
    for (const m of metrics) head += "<th>" + escapeHtml(metricShort(m)) + "</th>";
    head += '<th class="col-overall">Union</th><th>Errors</th>';
    tbl.querySelector("thead tr").innerHTML = head;
    let body = "";
    for (const d of decs) {
        let row = '<tr><td class="lb-name" title="' + escapeHtml(decTip(d)) + '">' + decNameHtml(d) + '</td>';
        for (const m of metrics) row += '<td class="metric-cell" data-label="' + escapeHtml(metricShort(m)) + '">' + cellPctHtml(metricCell(result, d, m)) + '</td>';
        row += '<td class="metric-cell col-overall" data-label="Union">' + cellPctHtml(overallCell(result, d)) + '</td>';
        row += '<td class="metric-cell" data-label="Errors">' + errorCellHtml(errorCell(result, d)) + '</td>';
        row += '</tr>';
        body += row;
    }
    tbl.querySelector("tbody").innerHTML = body;
}

function buildDistance(result) {
    const tbl = document.getElementById("distance-table");
    if (!tbl) return;
    const groups = splitDecs(), metrics = orderedMetrics(), dist = result.distance || {};
    let head = "<th>decompiler</th>";
    for (const m of metrics) head += "<th>" + escapeHtml(metricShort(m)) + " dist</th>";
    tbl.querySelector("thead tr").innerHTML = head;
    const mkRows = ds => ds
        .map(d => ({d, cells: metrics.map(m => (dist[d] && dist[d][m]) || null)}))
        .sort((a, b) => {
            const av = a.cells[0] ? a.cells[0].mean : Infinity;
            const bv = b.cells[0] ? b.cells[0].mean : Infinity;
            return av - bv;
        });
    const rows = mkRows(groups.main), subRows = mkRows(groups.subset);
    const best = {};
    metrics.forEach((m, i) => {
        best[m] = Math.min.apply(null, rows.map(r => r.cells[i] ? r.cells[i].mean : Infinity));
    });
    const rowHtml = (r, isSubset) => {
        let row = '<tr class="binrow' + (isSubset ? ' subset-row' : '') +
            '"><td class="lb-name" title="' +
            escapeHtml(decTip(r.d)) + '">' + decNameHtml(r.d) + '</td>';
        r.cells.forEach((st, i) => {
            const lbl = escapeHtml(metricShort(metrics[i]) + " dist");
            if (!st) { row += '<td class="metric-cell" data-label="' + lbl + '">&mdash;</td>'; return; }
            const isBest = !isSubset && st.mean <= best[metrics[i]] + 1e-9;
            row += '<td class="metric-cell" data-label="' + lbl + '">' +
                '<span class="cell-pct ' + (isBest ? 'pct-high' : '') + '">' +
                st.mean.toFixed(1) + '</span> ' +
                '<span class="cell-count">med ' + st.median + ' &middot; ' +
                st.at0 + '/' + st.n + ' at 0</span></td>';
        });
        return row + '</tr>';
    };
    let body = "";
    for (const r of rows) body += rowHtml(r, false);
    if (subRows.length) {
        body += subsetBreakRow(metrics.length + 1);
        for (const r of subRows) body += rowHtml(r, true);
    }
    tbl.querySelector("tbody").innerHTML = body;
    toggleSubsetNote("distance-subset-note", subRows.length > 0);
}

function buildCompile(result) {
    const tbl = document.getElementById("compile-table");
    if (!tbl) return;
    const groups = splitDecs();
    tbl.querySelector("thead tr").innerHTML = "<th>decompiler</th><th>Compiles</th>";
    const mkRows = ds => ds
        .map(d => ({d, cell: compileCell(result, d)}))
        .sort((a, b) => pct(b.cell) - pct(a.cell));
    const rowHtml = (r, isSubset) =>
        '<tr class="binrow' + (isSubset ? ' subset-row' : '') +
        '"><td class="lb-name" title="' +
        escapeHtml(decTip(r.d)) + '">' + decNameHtml(r.d) + '</td>' +
        '<td class="metric-cell" data-label="Compiles">' + cellPctHtml(r.cell) + '</td></tr>';
    const rows = mkRows(groups.main), subRows = mkRows(groups.subset);
    let body = "";
    for (const r of rows) body += rowHtml(r, false);
    if (subRows.length) {
        body += subsetBreakRow(2);
        for (const r of subRows) body += rowHtml(r, true);
    }
    tbl.querySelector("tbody").innerHTML = body;
    toggleSubsetNote("compile-subset-note", subRows.length > 0);
}

function fmtSecs(s) {
    return s >= 100 ? Math.round(s) + " s" : s.toFixed(1) + " s";
}
function buildCost() {
    const tbl = document.getElementById("cost-table");
    if (!tbl) return;
    const cost = (AGG && AGG.cost) || {};
    tbl.querySelector("thead tr").innerHTML =
        "<th>decompiler</th><th>median time / fn</th><th>mean time / fn</th><th>est. cost</th>";
    const all = ((AGG && AGG.decompilers) || []).filter(d => cost[d]);
    const sso = (AGG && AGG.sample_set_only) || [];
    const median = d => {
        const t = cost[d].time || {};
        return (t.median_s == null) ? Infinity : t.median_s;
    };
    const mkRows = ds => ds.slice().sort((a, b) => median(a) - median(b));
    const timeCell = v => (v == null) ? "&mdash;" : fmtSecs(v);
    const rowHtml = (d, isSubset) => {
        const t = cost[d].time || {}, dol = cost[d].dollars;
        const dolCell = dol
            ? '$' + dol.total.toFixed(2) + ' <span class="cell-count">($' +
              dol.per_function.toFixed(2) + '/fn, est.)</span>'
            : (isSubset ? 'n/a' : '&mdash;');
        return '<tr class="binrow' + (isSubset ? ' subset-row' : '') +
            '"><td class="lb-name" title="' + escapeHtml(decTip(d)) + '">' +
            decNameHtml(d) + '</td>' +
            '<td class="metric-cell" data-label="median time / fn">' + timeCell(t.median_s) + '</td>' +
            '<td class="metric-cell" data-label="mean time / fn">' + timeCell(t.mean_s) + '</td>' +
            '<td class="metric-cell" data-label="est. cost">' + dolCell + '</td></tr>';
    };
    const rows = mkRows(all.filter(d => sso.indexOf(d) < 0));
    const subRows = mkRows(all.filter(d => sso.indexOf(d) >= 0));
    let body = "";
    for (const d of rows) body += rowHtml(d, false);
    if (subRows.length) {
        body += subsetBreakRow(4);
        for (const d of subRows) body += rowHtml(d, true);
    }
    tbl.querySelector("tbody").innerHTML = body;
}

function updateStats(result) {
    const fnEl = document.querySelector('[data-stat="functions"]');
    if (fnEl) fnEl.textContent = result.functions.toLocaleString();
    const binEl = document.querySelector('[data-stat="binaries"]');
    if (binEl) binEl.textContent = result.binaries.toLocaleString();
    // A snapshot can carry a different set of either, so the sidebar counts come
    // from the loaded payload rather than from the page the renderer stamped.
    const decEl = document.querySelector('[data-stat="decompilers"]');
    if (decEl) decEl.textContent = String(((AGG && AGG.decompilers) || []).length);
    const metEl = document.querySelector('[data-stat="metrics"]');
    if (metEl) metEl.textContent = String(((AGG && AGG.metrics) || []).length);
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
        ["leaderboard", "about", "data"].forEach(v => showBanner(v,
            "No precomputed aggregates for dataset '" + (state.dataset || FALLBACK_PRESET) +
            "' with normalize=" + (state.normalize ? "on" : "off") + "."));
        return;
    }
    buildLeaderboard(lastResult);
    buildMetricsTable(lastResult);
    buildDistance(lastResult);
    buildCompile(lastResult);
    updateStats(lastResult);
    renderDatasetProjects();
}

let _lastDataset = null;
function buildDataset(ds) {
    const cats = ds.categories || [], summary = ds.summary || {};
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
    _lastDataset = ds;
    renderDatasetProjects();
}

function buildPipelineHealth(ds) {
    const joern = ds.joern || {};
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
}

function renderDatasetProjects() {
    const tbl = document.getElementById("dataset-projects");
    if (!tbl || !_lastDataset) return;
    let proj = (_lastDataset.projects || []).slice();
    const filtered = (state.dataset || defaultPresetName()) === SAMPLE_SET_PRESET;
    if (filtered) {
        proj = proj.filter(p => (p.presets || []).indexOf(SAMPLE_SET_PRESET) >= 0);
    }
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
    const note = document.getElementById("dataset-projects-note");
    if (note) {
        note.textContent = filtered ? (proj.length + " projects sampled into the sample-set.") : "";
    }
}

let VIEW_SAMPLES = [];
const DIFFICULTIES = ["easy", "medium", "hard", "sample-set"];
function sampleLabel(s) {
    return s.project + "/" + s.opt_level + "/" + s.binary + " :: " + s.function;
}
function sampleKey(s) {
    return s.project + "/" + s.opt_level + "/" + s.binary + "::" + s.function;
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
function sourceUnavailableReason(status) {
    switch (status) {
        case "binary_not_found":
            return "the compiled binary for this sample is no longer on disk";
        case "no_source_files":
            return "no source files were captured next to this binary at compile time";
        case "func_not_in_sources":
            return "the function's defining source file was not captured next to the binary (generated or nested source)";
        case "extract_failed":
            return "the function's definition could not be found in the captured sources (its translation unit was not captured)";
        default:
            return "source could not be extracted for this sample";
    }
}
function renderViewEntry() {
    const c = viewControls();
    if (!c.fn || !c.body) return;
    const s = VIEW_SAMPLES[parseInt(c.fn.value, 10)];
    if (!s) { c.body.innerHTML = '<p class="view-desc">No function selected.</p>'; return; }
    const dec = c.dec ? c.dec.value : "";
    const selMetric = c.metric ? c.metric.value : "";
    let html = '<div class="cmp-meta">' + escapeHtml(s.project) + '/' +
        escapeHtml(s.opt_level) + '/' + escapeHtml(s.binary) +
        ' &middot; ' + escapeHtml(s.function) +
        (s.size != null ? (' &middot; ' + s.size + ' lines') : '') +
        (s.difficulty ? (' &middot; <span class="tag score-bad">' +
            escapeHtml(s.difficulty) + '</span>') : '') +
        '</div>';
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
    html += '<div class="cmp-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">';
    if (s.source_code) {
        const badge = s.source_status === "preprocessed"
            ? '<div class="src-badge">from preprocessed (.i) source &mdash; macros expanded</div>'
            : '';
        html += '<div class="cmp-col src"><h4>source (ground truth)</h4>' + badge +
            '<pre><code>' + hlC(s.source_code) + '</code></pre></div>';
    } else {
        html += '<div class="cmp-col src src-missing"><h4>source (ground truth)</h4>' +
            '<p class="view-desc">Source unavailable &mdash; ' +
            escapeHtml(sourceUnavailableReason(s.source_status)) + '</p></div>';
    }
    const withheld = (s.private || []).indexOf(dec) >= 0;
    let panel;
    if (code) {
        panel = '<pre><code>' + hlC(code) + '</code></pre>';
    } else if (withheld) {
        panel = '<p class="view-desc">private &mdash; ' + escapeHtml(decName(dec)) +
            ' submitted this function, but asked that their decompiled output not be ' +
            'published. The scores above are measured on the real output.</p>';
    } else {
        panel = '<p class="view-desc">No output from ' + escapeHtml(dec) +
            ' for this function.</p>';
    }
    html += '<div class="cmp-col' + (withheld ? ' src-missing' : '') + '"><h4>' +
        escapeHtml(dec) + '</h4>' + panel + '</div>';
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
    const tiers = DIFFICULTIES.filter(t => VIEW_SAMPLES.some(s => s.difficulty === t));
    if (c.tier) {
        (tiers.length ? tiers : ["__all__"]).forEach(t => {
            const o = document.createElement("option");
            o.value = t; o.textContent = t === "__all__" ? "all" : t;
            c.tier.appendChild(o);
        });
    }
    const decs = [];
    for (const s of VIEW_SAMPLES) {
        for (const d in (s.decompiled || {})) if (decs.indexOf(d) < 0) decs.push(d);
        for (const d of (s.private || [])) if (decs.indexOf(d) < 0) decs.push(d);
    }
    decs.sort();
    if (c.dec) {
        decs.forEach(d => {
            const o = document.createElement("option");
            o.value = d; o.textContent = decName(d);
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
    const fnIdx = applyViewParams(c);
    if (c.tier) c.tier.addEventListener("change", () => { fillViewFunctions(); syncUrl(); });
    if (c.dec) c.dec.addEventListener("change", () => { renderViewEntry(); syncUrl(); });
    if (c.metric) c.metric.addEventListener("change", () => { renderViewEntry(); syncUrl(); });
    c.fn.addEventListener("change", () => { renderViewEntry(); syncUrl(); });
    if (c.filter) c.filter.addEventListener("input", fillViewFunctions);
    fillViewFunctions();
    if (fnIdx >= 0 && Array.from(c.fn.options).some(o => o.value === String(fnIdx))) {
        c.fn.value = String(fnIdx);
        renderViewEntry();
    }
    if (state.view === "view") syncUrl();
}
function applyViewParams(c) {
    const optOf = sel => Array.from(sel.options).map(o => o.value);
    let fnIdx = -1;
    const fnP = INIT_PARAMS.get("fn");
    if (fnP) {
        for (let i = 0; i < VIEW_SAMPLES.length; i++) {
            if (sampleKey(VIEW_SAMPLES[i]) === fnP) { fnIdx = i; break; }
        }
    }
    if (c.tier) {
        let t = INIT_PARAMS.get("tier");
        if (fnIdx >= 0 && VIEW_SAMPLES[fnIdx].difficulty) t = VIEW_SAMPLES[fnIdx].difficulty;
        if (t && optOf(c.tier).indexOf(t) >= 0) c.tier.value = t;
    }
    const decP = INIT_PARAMS.get("dec");
    if (c.dec && decP && optOf(c.dec).indexOf(decP) >= 0) c.dec.value = decP;
    const metricP = INIT_PARAMS.get("metric");
    if (c.metric && metricP && optOf(c.metric).indexOf(metricP) >= 0) c.metric.value = metricP;
    return fnIdx;
}

/* ---- Snapshots: the notice, and the /snapshots/ listing --------------------
 * Every record read here is one index.json entry — snapshots.py's _build_meta
 * output — so a row describes the day it was taken (its own decompiler names and
 * versions), never today's registry, which AGG may not even be holding.
 */
const SNAP_ANY = "__any__";
const SNAP_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
let SNAPSHOT_LIST = [];
let _snapMeta = null;
let _snapNoticeOn = false;

function snapDateLabel(name) {
    const m = SNAPSHOT_RE.test(name || "") ? String(name).split("-") : null;
    if (!m) return name || "";
    const mon = SNAP_MONTHS[parseInt(m[1], 10) - 1] || m[1];
    return parseInt(m[0], 10) + " " + mon + " " + m[2];
}
function snapshotHref(date) {
    const q = "?snapshot=" + encodeURIComponent(date);
    return (ROOT !== null) ? (basePath() + "leaderboard/" + q) : q;
}
function snapshotsListUrl() {
    return (ROOT !== null) ? (basePath() + "snapshots/") : "#snapshots";
}
// The current view with the snapshot dropped — the way back to live.
function snapshotLiveUrl() {
    const params = new URLSearchParams(currentQuery());
    params.delete("snapshot");
    const qs = params.toString();
    if (ROOT !== null) return basePath() + (state.view ? state.view + "/" : "") + (qs ? "?" + qs : "");
    return location.pathname + (qs ? "?" + qs : "") + (location.hash || "");
}
function snapshotLinksHtml() {
    return '<a href="' + escapeHtml(snapshotLiveUrl()) + '">back to live</a> &middot; ' +
        '<a href="' + escapeHtml(snapshotsListUrl()) + '">all snapshots</a>';
}
function renderSnapshotNotice(meta) {
    const el = document.getElementById("snapshot-notice");
    if (!el || !SNAPSHOT) return;
    _snapMeta = meta || _snapMeta;
    const label = _snapMeta && _snapMeta.label;
    el.innerHTML = "[ snapshot ] Viewing the scoreboard as of " +
        escapeHtml(snapDateLabel(SNAPSHOT)) + "." +
        (label ? (" " + escapeHtml(label)) : "") + " " + snapshotLinksHtml();
    el.hidden = false;
    _snapNoticeOn = true;
}
// Shown only once the frozen aggregates are in hand: a missing snapshot must
// banner as missing (below), never announce itself as a frozen scoreboard.
function initSnapshotNotice() {
    if (!SNAPSHOT) return;
    renderSnapshotNotice(null);
    loadData("snapshots").then(list => {
        const meta = (list || []).filter(m => m && m.date === SNAPSHOT)[0];
        if (meta) renderSnapshotNotice(meta);
    }).catch(() => { });
}
function snapshotMissingHtml() {
    return "[ error ] No snapshot was recorded for " + escapeHtml(snapDateLabel(SNAPSHOT)) +
        " (" + escapeHtml(SNAPSHOT) + "). Live numbers are deliberately NOT shown under a " +
        "snapshot URL. " + snapshotLinksHtml();
}
function snapshotViewNotice(body) {
    body.innerHTML = '<p class="view-desc">Source samples are not part of a snapshot &mdash; ' +
        'they are ~31&nbsp;MB per day, so only the scoreboard payloads are frozen. ' +
        '<a href="' + escapeHtml(snapshotLiveUrl()) + '">Open the live view page</a> ' +
        'for source next to decompiler output.</p>';
}

function addOption(sel, value, label) {
    const o = document.createElement("option");
    o.value = value; o.textContent = label;
    sel.appendChild(o);
}
function optValues(sel) { return Array.from(sel.options).map(o => o.value); }
function snapDecName(meta, dec) { return (meta.decompiler_names || {})[dec] || dec; }
function snapVerText(v) { return v ? (/^\d/.test(v) ? "v" + v : v) : ""; }
function snapDecHtml(meta, dec) {
    const v = snapVerText((meta.decompiler_versions || {})[dec]);
    return escapeHtml(snapDecName(meta, dec)) + (v ? (" " + escapeHtml(v)) : "");
}
function snapVersionsHtml(meta, dec) {
    const decs = meta.decompilers || [];
    if (dec !== SNAP_ANY) {
        return decs.indexOf(dec) >= 0 ? snapDecHtml(meta, dec) : "&mdash;";
    }
    return decs.length ? decs.map(d => snapDecHtml(meta, d)).join(" &middot; ") : "&mdash;";
}
function snapLeadersHtml(meta) {
    const leaders = meta.leaders || [];
    if (!leaders.length) return "&mdash;";
    return leaders.map((l, i) => {
        const p = Number(l && l.pct) || 0;
        return '<span class="snap-leader"><span class="cell-count">' + (i + 1) + '.</span> ' +
            escapeHtml((l && (l.name || l.dec)) || "?") +
            ' <span class="cell-pct pct-' + pctClass(p) + '">' + p.toFixed(1) + '%</span></span>';
    }).join(" ");
}
function snapMatches(meta, dec, ver) {
    if (dec === SNAP_ANY) return true;
    if ((meta.decompilers || []).indexOf(dec) < 0) return false;
    if (ver === SNAP_ANY) return true;
    return (meta.decompiler_versions || {})[dec] === ver;
}
function fillSnapDecs(sel) {
    const names = {};
    SNAPSHOT_LIST.forEach(m => (m.decompilers || []).forEach(d => {
        if (!(d in names)) names[d] = snapDecName(m, d);
    }));
    const ids = Object.keys(names)
        .sort((a, b) => names[a].localeCompare(names[b]) || a.localeCompare(b));
    sel.innerHTML = "";
    addOption(sel, SNAP_ANY, "any");
    ids.forEach(d => addOption(sel, d, names[d]));
}
function fillSnapVersions(sel, dec) {
    if (!sel) return;
    sel.innerHTML = "";
    addOption(sel, SNAP_ANY, "any");
    if (dec === SNAP_ANY) return;
    const vers = [];
    SNAPSHOT_LIST.forEach(m => {
        const v = (m.decompiler_versions || {})[dec];
        if (v && vers.indexOf(v) < 0) vers.push(v);
    });
    vers.sort().forEach(v => addOption(sel, v, v));
}
function snapRowHtml(meta, dec) {
    const label = meta.label || meta.note || "";
    return '<tr class="binrow"><td class="lb-name"><a href="' +
        escapeHtml(snapshotHref(meta.date)) + '" title="' + escapeHtml(meta.date) + '">' +
        escapeHtml(snapDateLabel(meta.date)) + '</a></td>' +
        '<td>' + (label ? escapeHtml(label) : "&mdash;") + '</td>' +
        '<td>' + (Number(meta.functions) || 0).toLocaleString() + '</td>' +
        '<td class="cell-count snap-versions">' + snapVersionsHtml(meta, dec) + '</td>' +
        '<td class="snap-leaders">' + snapLeadersHtml(meta) + '</td></tr>';
}
function renderSnapshotsTable() {
    const body = document.getElementById("snapshots-body");
    if (!body) return;
    const decSel = document.getElementById("snap-dec"), verSel = document.getElementById("snap-ver");
    const dec = decSel ? decSel.value : SNAP_ANY, ver = verSel ? verSel.value : SNAP_ANY;
    const rows = SNAPSHOT_LIST.filter(m => snapMatches(m, dec, ver));
    let html = '<table id="snapshots-table"><thead><tr><th>date</th><th>label</th>' +
        '<th>functions</th><th>decompiler versions</th><th>leaders</th></tr></thead><tbody>';
    if (!rows.length) {
        html += '<tr><td colspan="5" class="snap-empty">No snapshots match this filter.</td></tr>';
    } else {
        rows.forEach(m => { html += snapRowHtml(m, dec); });
    }
    body.innerHTML = html + "</tbody></table>";
    const count = document.getElementById("snap-count");
    if (count) count.textContent = rows.length + " / " + SNAPSHOT_LIST.length + " snapshots";
}
// index.json is already newest-first; rendering never re-sorts it.
function buildSnapshots(list) {
    SNAPSHOT_LIST = Array.isArray(list) ? list.filter(m => m && m.date) : [];
    const body = document.getElementById("snapshots-body");
    if (!body) return;
    const filters = document.getElementById("snap-filters");
    if (!SNAPSHOT_LIST.length) {
        body.innerHTML = '<p class="view-desc">No snapshots have been recorded yet.</p>';
        if (filters) filters.hidden = true;
        return;
    }
    const decSel = document.getElementById("snap-dec"), verSel = document.getElementById("snap-ver");
    if (decSel) {
        fillSnapDecs(decSel);
        const wantDec = INIT_PARAMS.get("dec");
        if (wantDec && optValues(decSel).indexOf(wantDec) >= 0) decSel.value = wantDec;
        fillSnapVersions(verSel, decSel.value);
        decSel.addEventListener("change", () => {
            fillSnapVersions(verSel, decSel.value);
            renderSnapshotsTable();
            syncUrl();
        });
    }
    if (verSel) {
        const wantVer = INIT_PARAMS.get("ver");
        if (wantVer && optValues(verSel).indexOf(wantVer) >= 0) verSel.value = wantVer;
        verSel.addEventListener("change", () => { renderSnapshotsTable(); syncUrl(); });
    }
    if (filters) filters.hidden = false;
    renderSnapshotsTable();
}

function baseName(dec) { const a = dec.indexOf("@"); return a >= 0 ? dec.substring(0, a) : dec; }

function currentTheme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}
function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("decbench-theme", theme); } catch (e) { }
}
function initThemeToggle() {
    const btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", () => {
        applyTheme(currentTheme() === "light" ? "dark" : "light");
    });
}

// `independent` views render without the aggregates payload: the snapshot listing
// is exactly what a bad ?snapshot= sends people to, so it must survive one.
const LAZY_VIEWS = {
    about: {file: "dataset", body: "dataset-summary", render: buildDataset},
    data: {file: "dataset", body: "joern-source", render: buildPipelineHealth},
    view: {file: "samples", body: "view-body", render: initView},
    snapshots: {file: "snapshots", body: "snapshots-body", render: buildSnapshots,
                independent: true}
};
const lazyStarted = {};
function ensureViewData(name) {
    const spec = LAZY_VIEWS[name];
    if (!spec || lazyStarted[name]) return;
    const body = document.getElementById(spec.body);
    if (!body) return;
    lazyStarted[name] = true;
    if (SNAPSHOT && name === "view") { snapshotViewNotice(body); return; }
    setLoading(body);
    const needed = spec.independent
        ? [loadData(spec.file)]
        : [loadData("aggregates"), loadData(spec.file)];
    Promise.all(needed)
        .then(loaded => spec.render(loaded[loaded.length - 1]))
        .catch(err => {
            body.innerHTML = "";
            showBanner(name, "Could not load " + dataPath(spec.file) + " — " + err.message);
        });
}

function showView(name) {
    state.view = name;
    document.querySelectorAll(".view").forEach(v => {
        v.classList.toggle("active", v.getAttribute("data-view") === name);
    });
    document.querySelectorAll(".nav-item").forEach(a => {
        a.classList.toggle("active", a.getAttribute("data-view") === name);
    });
    if (_snapNoticeOn) renderSnapshotNotice(null);
    ensureViewData(name);
}
function validViews() {
    return Array.from(document.querySelectorAll(".view")).map(v => v.getAttribute("data-view"));
}
const LEGACY_HASH_VIEWS = {distance: "data"};
function resolveViewHash(hash) {
    const views = validViews();
    if (views.indexOf(hash) >= 0) return hash;
    const mapped = LEGACY_HASH_VIEWS[hash];
    return (mapped && views.indexOf(mapped) >= 0) ? mapped : null;
}
// The default view is config (views.toml's `default = true`) and reaches us
// through the DOM: routing runs before aggregates.json lands.
// views.toml's `default = true` — and reaches us through the DOM: the renderer
// marks that section `active` (on a subpage, the subpage's own view), and routing
// runs before aggregates.json lands, so we cannot wait to read it from there.
function defaultView() {
    const el = document.querySelector(".view.active") || document.querySelector(".view");
    return el ? el.getAttribute("data-view") : null;
}
// The source of truth AFTER a browser navigation, when the DOM's `.active` is
// stale.
// (the root, or an unknown segment). The source of truth AFTER a browser navigation,
// when the DOM's `.active` is stale.
function pathView() {
    if (ROOT === null) return null;
    let rest = location.pathname;
    const bp = basePath();
    if (rest.indexOf(bp) === 0) rest = rest.slice(bp.length);
    rest = rest.replace(/index\.html$/, "").replace(/^\/+|\/+$/g, "");
    const seg = rest.split("/")[0];
    return validViews().indexOf(seg) >= 0 ? seg : null;
}
function routeTarget() {
    const hash = (location.hash || "").replace("#", "");
    return resolveViewHash(hash) || defaultView();
}
function viewUrl(view) {
    const qs = currentQuery();
    if (ROOT !== null) return basePath() + (view ? view + "/" : "") + (qs ? "?" + qs : "");
    return location.pathname + (qs ? "?" + qs : "") + (location.hash || "");
}
function writeUrl(push) {
    const url = viewUrl(state.view);
    try {
        if (push) history.pushState({view: state.view}, "", url);
        else history.replaceState(history.state, "", url);
    } catch (e) { }
}
function syncUrl() { writeUrl(false); }
function navigate(view) {
    showView(view);
    writeUrl(ROOT !== null);
}
function onPopState() {
    const hash = (location.hash || "").replace("#", "");
    const name = resolveViewHash(hash)
        || pathView() || (AGG && AGG.default_view) || defaultView();
    if (name) showView(name);
}
function onHashChange() {
    const hash = (location.hash || "").replace("#", "");
    const name = resolveViewHash(hash);
    if (name) showView(name);
    maybeScrollToHash();
}
// The browser's native on-load scroll fires while these sections are still
// empty, so re-scroll once the async tables have rendered.
// the old /distance/ URL that now redirects to /data/#distance) must scroll to its
// heading AFTER the async tables render: the browser's native on-load scroll fires
// while those sections are still empty, so the heading has moved by the time the
// content lands. Re-scroll once. A hash that names a VIEW (routing's job) is skipped.
function maybeScrollToHash() {
    const id = (location.hash || "").replace("#", "");
    if (!id || validViews().indexOf(id) >= 0) return;
    const el = document.getElementById(id);
    if (el) el.scrollIntoView();
}
function initNav() {
    const views = validViews();
    document.querySelectorAll(".nav-item").forEach(a => {
        const id = a.getAttribute("data-view");
        // Rewrite the href to the real subpage URL so middle-click / copy-link work
        // (the renderer ships "#id" for the no-JS and single-file forms). The id is
        // DOM text, so it is checked against the rendered view set and encoded before
        // it reaches an href — an unchecked one is a URL-injection sink.
        if (ROOT !== null && views.indexOf(id) >= 0) {
            const qs = currentQuery();
            const href = basePath() + encodeURIComponent(id) + "/" + (qs ? "?" + qs : "");
            try { a.setAttribute("href", href); } catch (e) {}
        }
        a.addEventListener("click", e => {
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || (e.button && e.button !== 0)) return;
            e.preventDefault();
            navigate(id);
        });
    });
    // No samples are frozen, so the view page is dimmed — but still reachable.
    if (SNAPSHOT) {
        const vi = document.querySelector('.nav-item[data-view="view"]');
        if (vi) vi.classList.add("nav-item-muted");
    }
    if (ROOT !== null) window.addEventListener("popstate", onPopState);
    window.addEventListener("hashchange", onHashChange);
    const target = routeTarget();
    if (target) showView(target);
}

function defaultPresetName() {
    const presets = (AGG && AGG.presets) || [];
    const def = presets.filter(p => p.default)[0] || presets[0];
    return def ? def.name : null;
}
function currentQuery() {
    const params = new URLSearchParams();
    if (SNAPSHOT) params.set("snapshot", SNAPSHOT);
    if (state.dataset && state.dataset !== defaultPresetName()) params.set("dataset", state.dataset);
    if (state.normalize) params.set("norm", "1");
    if (state.view === "view") {
        const c = viewControls();
        if (c.tier && c.tier.value && c.tier.value !== "__all__") params.set("tier", c.tier.value);
        if (c.dec && c.dec.value) params.set("dec", c.dec.value);
        if (c.metric && c.metric.value) params.set("metric", c.metric.value);
        const s = c.fn ? VIEW_SAMPLES[parseInt(c.fn.value, 10)] : null;
        if (s) params.set("fn", sampleKey(s));
    }
    if (state.view === "snapshots") {
        const d = document.getElementById("snap-dec"), v = document.getElementById("snap-ver");
        if (d && d.value && d.value !== SNAP_ANY) params.set("dec", d.value);
        if (v && v.value && v.value !== SNAP_ANY) params.set("ver", v.value);
    }
    return params.toString();
}

function setDatasetDesc() {
    const p = (AGG.presets || []).filter(x => x.name === state.dataset)[0];
    const el = document.getElementById("dataset-desc");
    if (el) el.textContent = p ? p.description : "";
    // `long_description` is packaged, maintainer-authored inline HTML from
// content/datasets.toml — not run data — so innerHTML is safe here.
    // final inline HTML from content/datasets.toml (packaged, maintainer-authored
    // — not run data), so innerHTML is safe; empty (older aggregates.json or an
    // unregistered preset) renders nothing.
    const lb = document.getElementById("leaderboard-dataset-desc");
    if (lb) {
        const html = p && p.long_description;
        lb.innerHTML = html ? '<p class="view-desc">' + html + "</p>" : "";
    }
}
function initDatasetSelector() {
    const presets = AGG.presets || [];
    const def = presets.filter(p => p.default)[0] || presets[0];
    const wanted = INIT_PARAMS.get("dataset");
    state.dataset = presets.some(p => p.name === wanted) ? wanted : (def ? def.name : null);
    state.normalize = INIT_PARAMS.get("norm") === "1";
    const btns = document.querySelectorAll(".ds-btn[data-dataset]");
    btns.forEach(b => {
        b.classList.toggle("active", b.getAttribute("data-dataset") === state.dataset);
        b.addEventListener("click", () => {
            state.dataset = b.getAttribute("data-dataset");
            btns.forEach(x => x.classList.remove("active"));
            b.classList.add("active");
            setDatasetDesc();
            syncUrl();
            refresh();
        });
    });
    setDatasetDesc();
    const nb = document.getElementById("normalize-btn");
    if (nb) {
        nb.classList.toggle("active", state.normalize);
        nb.addEventListener("click", () => {
            state.normalize = !state.normalize;
            nb.classList.toggle("active", state.normalize);
            syncUrl();
            refresh();
        });
    }
}

function init() {
    initNav();
    initThemeToggle();
    if (typeof applyStaticHighlights === "function") applyStaticHighlights(document);
    loadData("aggregates").then(agg => {
        AGG = agg;
        initDatasetSelector();
        refresh();
        buildCost();
        initSnapshotNotice();
        maybeScrollToHash();
    }).catch(err => {
        const views = ["leaderboard", "about", "data"];
        if (SNAPSHOT) {
            views.forEach(v => showBannerHtml(v, snapshotMissingHtml()));
            return;
        }
        views.forEach(v => showBanner(v,
            "Could not load data/aggregates.json — " + err.message +
            ". this view has no data."));
    });
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
