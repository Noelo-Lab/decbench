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

/* ============================================================================
 * Self-contained syntax highlighter — no third-party code, no CDN.
 *
 * An IIFE that exposes three globals on `window` (this file is a classic
 * script, so they are reachable as bare names below):
 *   hlC(code)                    -> HTML string  (C / decompiler pseudo-C)
 *   hlAsm(text)                  -> HTML string  (x86-64 Intel + basic ARM)
 *   applyStaticHighlights(root)  -> highlight every <pre data-lang="c|asm">
 *                                   under `root` by reading its textContent.
 *
 * Token span classes (styled in app.css): tok-kw tok-type tok-str tok-num
 * tok-com tok-pp tok-call tok-mn tok-reg tok-imm tok-lbl.
 *
 * The tokenizers escape every token's text and clamp unterminated strings /
 * comments to EOL/EOF, so output is always well-formed even on adversarial
 * input (< > & " '). init() drives applyStaticHighlights(document) (there is no
 * DOMContentLoaded auto-init here — see the source viz/hl.js), so the about
 * page's server-rendered <pre data-lang> blocks are highlighted in both the
 * split and inline delivery modes.
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

  // ---- C keyword / type vocabularies -------------------------------------
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
    // real C types
    "void", "char", "short", "int", "long", "float", "double", "bool",
    "size_t", "ssize_t", "ptrdiff_t", "wchar_t", "va_list", "FILE", "off_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "intptr_t", "uintptr_t",
    // decompiler pseudo-types (Ghidra / IDA / angr / binja flavours)
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

  // -------------------------------------------------------------------------
  //  C / pseudo-C
  // -------------------------------------------------------------------------
  function hlC(code) {
    code = String(code == null ? "" : code);
    var out = "", plain = "", i = 0, n = code.length;
    var atLineStart = true;            // only whitespace seen since last '\n'
    function flush() { if (plain) { out += esc(plain); plain = ""; } }

    while (i < n) {
      var c = code[i];

      // preprocessor line: '#' as the first non-space token on a line
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
      // line comment
      if (c === "/" && code[i + 1] === "/") {
        flush();
        var k = code.indexOf("\n", i); if (k < 0) k = n;
        out += span("tok-com", code.slice(i, k));
        i = k; continue;
      }
      // block comment
      if (c === "/" && code[i + 1] === "*") {
        flush();
        var e = code.indexOf("*/", i + 2); e = (e < 0) ? n : e + 2;
        out += span("tok-com", code.slice(i, e));
        i = e; atLineStart = false; continue;
      }
      // string / char literal
      if (c === '"' || c === "'") {
        flush();
        var q = c, p = i + 1;
        while (p < n) {
          if (code[p] === "\\") { p += 2; continue; }
          if (code[p] === q || code[p] === "\n") break;
          p++;
        }
        if (code[p] === q) p++;        // include closing quote when present
        out += span("tok-str", code.slice(i, p));
        i = p; atLineStart = false; continue;
      }
      // number (hex / decimal / float, with suffixes)
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
      // identifier / keyword / type / call
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
      // plain char (operators, punctuation, whitespace)
      if (c === "\n") { plain += c; atLineStart = true; i++; continue; }
      if (!isSpaceNoNL(c)) atLineStart = false;
      plain += c; i++;
    }
    flush();
    return out;
  }

  // -------------------------------------------------------------------------
  //  Assembly (x86-64 Intel-syntax + basic ARM)
  // -------------------------------------------------------------------------
  var X86_REGS = new Set([
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
    "sil", "dil", "bpl", "spl",
    "lr", "pc", "fp", "ip", "sb", "sl", "xzr", "wzr"   // ARM aliases
  ]);
  function isReg(w) {
    var r = w.toLowerCase();
    if (X86_REGS.has(r)) return true;
    if (/^r\d{1,2}[dwb]?$/.test(r)) return true;         // r0..r15, r8d/r9w/..
    if (/^[xw]([0-9]|[12][0-9]|3[01])$/.test(r)) return true; // ARM x0..x31/w0..
    if (/^(xmm|ymm|zmm)\d{1,2}$/.test(r)) return true;   // SIMD
    if (/^[dsq]([0-9]|[12][0-9]|3[01])$/.test(r)) return true; // ARM d/s/q regs
    return false;
  }

  function readNumTail(line, s) {          // s points just past the # / $ prefix
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
    // leading whitespace
    var ws = 0; while (ws < n && (line[ws] === " " || line[ws] === "\t")) ws++;
    if (ws) { out += esc(line.slice(0, ws)); i = ws; }

    // leading label:  name:  /  .Lxx:  /  hexaddr:
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
      // comments
      if (c === ";" || c === "@") { out += span("tok-com", line.slice(i)); break; }
      if (c === "/" && line[i + 1] === "/") { out += span("tok-com", line.slice(i)); break; }
      if (c === "#") {
        var d = line[i + 1];
        if (d === "-" || d === "+" || (d >= "0" && d <= "9")) {   // #imm
          var s = readNumTail(line, i + 1);
          out += span("tok-imm", line.slice(i, s)); i = s; continue;
        }
        out += span("tok-com", line.slice(i)); break;            // '# comment'
      }
      // whitespace
      if (c === " " || c === "\t") {
        var a = i; while (i < n && (line[i] === " " || line[i] === "\t")) i++;
        out += esc(line.slice(a, i)); continue;
      }
      // AT&T immediate  $imm
      if (c === "$") {
        var s2 = readNumTail(line, i + 1);
        out += span("tok-imm", line.slice(i, s2)); i = s2; continue;
      }
      // bare number / hex
      if (isDigit(c)) {
        var s3 = i;
        if (c === "0" && (line[i + 1] === "x" || line[i + 1] === "X")) {
          i += 2; while (i < n && isHex(line[i])) i++;
        } else {
          while (i < n && isDigit(line[i])) i++;
        }
        out += span("tok-imm", line.slice(s3, i)); continue;
      }
      // word: mnemonic / directive / register / symbol
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
      // any other char (brackets, commas, +, -, *, :, !, etc.)
      out += esc(c); i++;
    }
    return out;
  }

  function hlAsm(text) {
    text = String(text == null ? "" : text);
    return text.split("\n").map(hlAsmLine).join("\n");
  }

  // -------------------------------------------------------------------------
  //  Static application to <pre data-lang="c|asm"> blocks
  // -------------------------------------------------------------------------
  function applyStaticHighlights(root) {
    root = root || (typeof document !== "undefined" ? document : null);
    if (!root) return;
    var pres = root.querySelectorAll("pre[data-lang]");
    for (var i = 0; i < pres.length; i++) {
      var pre = pres[i];
      if (pre.getAttribute("data-hl") === "1") continue;   // idempotent
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

// The inline payload, or null in split mode. Set before this script runs.
const INLINE = (typeof window !== "undefined" && window.__DECBENCH_INLINE__) || null;

// Split-mode routing root: the relative hop from THIS page to the site root,
// stamped by the renderer (html.py::linked_assets) before this script — "" on the
// root index, "../" on a `<view>/index.html` subpage. It is a string only in split
// mode; null in the single-file/inline report, which keeps pure hash routing.
const ROOT = (typeof window !== "undefined" && typeof window.__DECBENCH_ROOT__ === "string")
    ? window.__DECBENCH_ROOT__ : null;

// Query params from the URL the page FIRST loaded with, read once before any
// replaceState rewrites location: dataset/norm, and on the view page tier/dec/
// metric/fn. Unknown values are ignored where they are applied, never here.
const INIT_PARAMS = (function () {
    try { return new URLSearchParams(location.search); } catch (e) { return new URLSearchParams(); }
})();

// The directory of the SITE ROOT (e.g. "/decbench/"), resolved once from the page
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
// Resolve NOW, before any pushState moves location: a later first call would
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
        // Anchored to the site root, not the document: a relative "data/..." would
        // re-resolve against whatever path pushState/replaceState moved us to, and
        // the first cached rejection would stick for the whole session.
        const prefix = ROOT !== null ? basePath() : "";
        p = fetch(prefix + "data/" + name + ".json").then(r => {
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

// ---- Decompiler presentation (from the registry in aggregates.json) ----
// Official names / links / prettified versions replace raw ids on screen. Tolerant
// the same way metricSpecs is: a missing registry (older payload) or an unknown id
// (r2dec/dewolf data landing before its entry) falls back to the raw id, unlinked.
function decRegistry() { return (AGG && AGG.decompiler_registry) || {}; }
function decRegEntry(id) {
    const reg = decRegistry();
    if (reg[id]) return reg[id];
    // Base-name fallback: the history legend keys by base ("ghidra"), the registry
    // by full id ("ghidra@12.1"); resolve one to the other.
    const base = baseName(id);
    if (reg[base]) return reg[base];
    for (const k in reg) if (baseName(k) === base) return reg[k];
    return null;
}
function decName(id) { const e = decRegEntry(id); return (e && e.display_name) || id; }
function decUrl(id) { const e = decRegEntry(id); return (e && e.url) || null; }
function decVersion(id) {
    const e = decRegEntry(id);
    if (e && e.version) return e.version;
    return (AGG && AGG.decompiler_versions && AGG.decompiler_versions[id]) || null;
}
// Tooltip: pretty name + pretty version (was the raw id + raw version).
function decTip(id) {
    const v = decVersion(id);
    return v ? (decName(id) + " — version " + v) : decName(id);
}
// A decompiler as a table cell: linked when the registry carries a url (opens in a
// new tab; styled to keep the terminal look — see .lb-name a), plus a muted version.
function decNameHtml(id) {
    const name = escapeHtml(decName(id)), url = decUrl(id), v = decVersion(id);
    const nameHtml = url
        ? '<a href="' + escapeHtml(url) + '" target="_blank" rel="noopener">' + name + '</a>'
        : name;
    // "v" only in front of a number: "v9.2" reads right, "vr2 6.0.8" does not.
    const vtxt = v ? (/^\d/.test(v) ? "v" + v : v) : null;
    return nameHtml + (vtxt ? ' <span class="ver">' + escapeHtml(vtxt) + '</span>' : '');
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
    if (key === "__name__") return decName(d);
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
        let row = '<tr class="binrow"><td class="lb-rank">#' + (i + 1) + '</td>' +
            '<td class="lb-name" title="' + escapeHtml(decTip(d)) + '">' + decNameHtml(d) + '</td>';
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
        let row = '<tr><td class="lb-name" title="' + escapeHtml(decTip(d)) + '">' + decNameHtml(d) + '</td>';
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
        let row = '<tr class="binrow"><td class="lb-name" title="' +
            escapeHtml(decTip(r.d)) + '">' + decNameHtml(r.d) + '</td>';
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
// The stable id used in the `fn` URL param: the label with no spaces around "::".
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
// Human explanation for a missing view-page source, keyed by the `source_status`
// code the sample carries (stamped by scoring/report_extras.py). Any unknown or
// null code falls back to a generic line rather than showing an empty panel.
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
    // Always a two-column grid: source on the left (or, when it is missing, a
    // short explanation of why), the chosen decompiler's output on the right.
    // Both code panels are syntax-highlighted — hlC escapes its input for us.
    html += '<div class="cmp-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">';
    if (s.source_code) {
        const badge = s.source_status === "preprocessed"
            ? '<div class="src-badge">from preprocessed (.i) source &mdash; macros expanded</div>'
            : '';
        html += '<div class="cmp-col src"><h4>source (ground truth)</h4>' + badge +
            '<pre><code>' + hlC(s.source_code) + '</code></pre></div>';
    } else {
        html += '<div class="cmp-col src src-missing"><h4>source (ground truth)</h4>' +
            '<p class="view-desc">source unavailable &mdash; ' +
            escapeHtml(sourceUnavailableReason(s.source_status)) + '</p></div>';
    }
    html += '<div class="cmp-col"><h4>' + escapeHtml(dec) + '</h4>' +
        (code ? ('<pre><code>' + hlC(code) + '</code></pre>')
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
            o.value = d; o.textContent = decName(d);  // value stays the raw id
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
    // Deep-link the tier/dec/metric selects from the initial URL; the function is
    // selected after fillViewFunctions lists it.
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
    // Reflect the resolved view state in the URL (idempotent; keeps a deep link
    // canonical and drops any unknown params the reader arrived with).
    if (state.view === "view") syncUrl();
}
// Apply the view page's URL params (once, from the initial load). Returns the
// VIEW_SAMPLES index the `fn` param names, or -1. Unknown values are ignored: a
// param only takes effect when it matches a real option, and a named function
// additionally forces its own difficulty tier so its option is actually listed.
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
        span.appendChild(sw); span.appendChild(document.createTextNode(decName(dn))); legend.appendChild(span);
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
// Two modes, one DOM update. Split mode reflects the view in the URL PATH
// (site/<view>/) so it is linkable and the back button works; the single-file /
// inline report keeps its pure #hash behavior. showView only touches the DOM; the
// URL is written by navigate()/syncUrl().
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
function validViews() {
    return Array.from(document.querySelectorAll(".view")).map(v => v.getAttribute("data-view"));
}
// The view a fresh load opens on when the URL names none. It is config —
// views.toml's `default = true` — and reaches us through the DOM: the renderer
// marks that section `active` (on a subpage, the subpage's own view), and routing
// runs before aggregates.json lands, so we cannot wait to read it from there.
function defaultView() {
    const el = document.querySelector(".view.active") || document.querySelector(".view");
    return el ? el.getAttribute("data-view") : null;
}
// Split mode: the view named by the path segment just under the site root, or null
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
// Where a fresh load lands: a valid legacy `#hash` (so old site/#about links keep
// working) wins; otherwise the renderer already marked the right section active
// (a path subpage, or the inline default), so the DOM fallback covers it.
function routeTarget() {
    const hash = (location.hash || "").replace("#", "");
    if (validViews().indexOf(hash) >= 0) return hash;
    return defaultView();
}
// The canonical URL for the current state. Split mode carries the view in the path;
// inline mode leaves the path+hash alone and only attaches the query.
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
    } catch (e) { /* file:// and sandboxed frames forbid the history API */ }
}
// A state change (dataset / normalize / view select) replaces — no new history
// entry. A nav pushes a new entry in split mode, replaces in inline (hash left as is).
function syncUrl() { writeUrl(false); }
function navigate(view) {
    showView(view);
    writeUrl(ROOT !== null);
}
function onPopState() {
    // The URL is the source of truth after Back/Forward; do not push again. A
    // legacy `#hash` entry (the URL a pre-subpage deep link loaded with) names
    // its view in the hash, not the path — honor it exactly as routeTarget() did.
    const hash = (location.hash || "").replace("#", "");
    const name = (validViews().indexOf(hash) >= 0 ? hash : null)
        || pathView() || (AGG && AGG.default_view) || defaultView();
    if (name) showView(name);
}
// In-page `#view` links in the prose (e.g. about.md's "see distance") change the
// hash without a popstate; route them in both delivery modes.
function onHashChange() {
    const hash = (location.hash || "").replace("#", "");
    if (validViews().indexOf(hash) >= 0) showView(hash);
}
function initNav() {
    document.querySelectorAll(".nav-item").forEach(a => {
        const id = a.getAttribute("data-view");
        // Rewrite the href to the real subpage URL so middle-click / copy-link work
        // (the renderer ships "#id" for the no-JS and single-file forms).
        if (ROOT !== null) { try { a.setAttribute("href", basePath() + id + "/"); } catch (e) {} }
        a.addEventListener("click", e => {
            // Leave modified clicks (new tab, download, non-primary button) to the href.
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || (e.button && e.button !== 0)) return;
            e.preventDefault();
            navigate(id);
        });
    });
    if (ROOT !== null) window.addEventListener("popstate", onPopState);
    window.addEventListener("hashchange", onHashChange);
    const target = routeTarget();
    if (target) showView(target);
}

// ---- URL <-> state (query params, both modes) ----
function defaultPresetName() {
    const presets = (AGG && AGG.presets) || [];
    const def = presets.filter(p => p.default)[0] || presets[0];
    return def ? def.name : null;
}
// Minimal, clean query for the current state: dataset only when NOT the default
// preset, norm only when on, and the view-page selectors only while on that page.
function currentQuery() {
    const params = new URLSearchParams();
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
    return params.toString();
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
    // positional; a valid `dataset` URL param overrides it (deep link), and an
    // unknown one is ignored. Sync the buttons so state and UI cannot disagree.
    const def = presets.filter(p => p.default)[0] || presets[0];
    const wanted = INIT_PARAMS.get("dataset");
    state.dataset = presets.some(p => p.name === wanted) ? wanted : (def ? def.name : null);
    state.normalize = INIT_PARAMS.get("norm") === "1";
    // Only the preset buttons carry data-dataset (the normalize toggle does not).
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
    // "normalize failures": restrict to functions every decompiler decompiled.
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
    // Color the about page's server-rendered <pre data-lang> blocks. They are in
    // the DOM from page load in both modes (all view sections ship in every page),
    // so this runs once here rather than via a DOMContentLoaded auto-init.
    if (typeof applyStaticHighlights === "function") applyStaticHighlights(document);
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
