"""Cost FACTS for the data page's cost section: decompile time + LLM token usage.

This module gathers *facts only* — seconds and token counts — into the
JSON-serializable ``FunctionData.cost_info`` blob (written by
``scripts/compute_cost_info.py``). No dollar amount is computed here: prices live
in ``decbench/rendering/content/pricing.toml`` and are applied at RENDER time
(:func:`decbench.rendering.aggregate._cost_block`), so a price correction needs
only a re-render, never a re-scan.

Two kinds of source, deliberately not comparable and labeled by ``basis``:

* **batch** (:func:`scan_decompile_times`) — the traditional decompilers. Each
  ``decompiled/<dec>_<bin>.toml`` header records the binary's whole-run wall time
  and function count, so per-function time is ``total_time / function_count``:
  an amortized batch rate, not a per-function measurement.
* **per-function** (:func:`scan_llm_traces` and the structured fields) — the LLM
  coding agents, timed one agentic call per function *including* tool use.

Structured-first: runs made after ``FunctionDecompilation`` grew ``time_seconds``
/ ``llm_tokens`` (2026-07-23) carry per-function cost in the decompiled TOMLs
themselves, and :func:`build_cost_info` PREFERS those
(:func:`scan_structured_costs`) over the trace-directory scan — the scans remain
the historical path for runs recorded before the fields existed.
"""

from __future__ import annotations

import json
import logging
import re
import statistics
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_l = logging.getLogger(__name__)

__all__ = [
    "build_cost_info",
    "parse_session_tokens",
    "scan_decompile_times",
    "scan_llm_traces",
    "scan_structured_costs",
]

#: Trace ``.md`` header lines written by ``llm_dec._save_trace``.
_TRACE_MODEL_RE = re.compile(r"^- model:\s*(?P<model>.+?)\s*$", re.MULTILINE)
_TRACE_STATUS_RE = re.compile(r"^- status:\s*(?P<status>ok|FAILED|TIMEOUT)\s*$", re.MULTILINE)
_TRACE_ELAPSED_RE = re.compile(r"^- elapsed:\s*(?P<secs>\d+(?:\.\d+)?)s\s*$", re.MULTILINE)

#: The four normalized token buckets every parser emits (pricing.toml's axes).
_TOKEN_KEYS = ("input", "cached_input", "cache_write", "output")


# ---------------------------------------------------------------------------
# Batch decompile times (the traditional decompilers)
# ---------------------------------------------------------------------------


def _read_toml_header(path: Path) -> dict[str, Any] | None:
    """Parse ONLY a decompiled-TOML's header (the lines before the first table).

    A decompiled TOML carries ~100 per-function ``["functions.<name>"]`` tables;
    across ~6k files a full :func:`toml.loads` dominates the scan. The header —
    ``binary``/``decompiler``/``total_time``/``function_count``/... — is exactly
    the lines before the first line starting with ``[``, so only that prefix is
    parsed. Returns ``None`` on any read/parse failure (skip, don't abort).
    """
    import toml

    try:
        lines: list[str] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("["):
                    break
                lines.append(line)
        header: dict[str, Any] = toml.loads("".join(lines))
        return header
    except Exception as e:  # noqa: BLE001 - one bad artifact must not kill the scan
        _l.debug("cost: unreadable decompiled TOML header %s: %s", path, e)
        return None


def _decompiled_tomls(tree: Path, opt_levels: Iterable[str]) -> list[Path]:
    """Every ``<tree>/<opt>/<proj>/decompiled/*.toml``, sorted for determinism."""
    out: list[Path] = []
    for opt in opt_levels:
        base = tree / opt
        if base.is_dir():
            out.extend(base.glob("*/decompiled/*.toml"))
    return sorted(out)


def scan_decompile_times(tree: Path, opt_levels: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Per-decompiler batch decompile-time facts from a results tree's artifacts.

    The decompiler id comes from the header's ``decompiler`` field — NOT the
    filename stem, which is ``<dec>_<binary>`` where both halves can contain
    underscores. A binary with a zero ``total_time`` or ``function_count``
    contributes nothing (no time was recorded, or nothing was decompiled).

    Per decompiler: total seconds, function/binary counts, the amortized mean
    (``sum(total) / sum(functions)``) and the median of the per-binary
    per-function rates (``total_time / function_count`` each).
    """
    totals: dict[str, float] = {}
    functions: dict[str, int] = {}
    binaries: dict[str, int] = {}
    rates: dict[str, list[float]] = {}

    for path in _decompiled_tomls(tree, opt_levels):
        header = _read_toml_header(path)
        if not header:
            continue
        dec = str(header.get("decompiler") or "")
        total_time = float(header.get("total_time") or 0.0)
        count = int(header.get("function_count") or 0)
        if not dec or total_time <= 0 or count <= 0:
            continue
        totals[dec] = totals.get(dec, 0.0) + total_time
        functions[dec] = functions.get(dec, 0) + count
        binaries[dec] = binaries.get(dec, 0) + 1
        rates.setdefault(dec, []).append(total_time / count)

    return {
        dec: {
            "total_s": totals[dec],
            "functions": functions[dec],
            "binaries": binaries[dec],
            "per_fn_mean_s": totals[dec] / functions[dec],
            "per_fn_median_s": statistics.median(rates[dec]),
            "basis": "batch",
        }
        for dec in sorted(totals)
    }


# ---------------------------------------------------------------------------
# LLM session token parsing (shared with llm_dec's structured capture)
# ---------------------------------------------------------------------------


def _claude_session_tokens(records: list[dict[str, Any]]) -> dict[str, int] | None:
    """Sum a Claude Code session's usage: every ``type == "assistant"`` record.

    ``cache_creation_input_tokens`` is the cache WRITE total; when only the
    ``cache_creation`` breakdown (``ephemeral_1h_input_tokens`` /
    ``ephemeral_5m_input_tokens``) is present, that sums to the same quantity —
    one or the other is counted, never both (no double count).
    """
    sums = dict.fromkeys(_TOKEN_KEYS, 0)
    seen = False
    for rec in records:
        if rec.get("type") != "assistant":
            continue
        usage = (rec.get("message") or {}).get("usage")
        if not isinstance(usage, dict):
            continue
        seen = True
        sums["input"] += int(usage.get("input_tokens") or 0)
        sums["cached_input"] += int(usage.get("cache_read_input_tokens") or 0)
        sums["output"] += int(usage.get("output_tokens") or 0)
        write = usage.get("cache_creation_input_tokens")
        if write is None:
            breakdown = usage.get("cache_creation")
            if isinstance(breakdown, dict):
                write = sum(int(v or 0) for v in breakdown.values())
        sums["cache_write"] += int(write or 0)
    return sums if seen else None


def _codex_session_tokens(records: list[dict[str, Any]]) -> dict[str, int] | None:
    """A Codex session's usage: the LAST ``payload.type == "token_count"`` record.

    Codex logs a running total, so only the final record counts. Its
    ``input_tokens`` INCLUDES ``cached_input_tokens`` — normalized here to
    uncached input so the pricing formula never double-charges the cached part —
    and ``output_tokens`` already includes reasoning tokens.
    """
    usage: dict[str, Any] | None = None
    for rec in records:
        payload = rec.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "token_count":
            continue
        total = (payload.get("info") or {}).get("total_token_usage")
        if isinstance(total, dict):
            usage = total
    if usage is None:
        return None
    input_tokens = int(usage.get("input_tokens") or 0)
    cached = int(usage.get("cached_input_tokens") or 0)
    return {
        "input": max(input_tokens - cached, 0),
        "cached_input": cached,
        "cache_write": 0,
        "output": int(usage.get("output_tokens") or 0),
    }


def parse_session_tokens(path: Path) -> dict[str, int] | None:
    """Normalized token counts from one agent-CLI session JSONL, or ``None``.

    Sniffs the format per file — Claude Code (per-record ``message.usage``) first,
    then Codex (running ``token_count`` totals) — and degrades gracefully to
    ``None`` for an unknown future backend's log rather than guessing. The
    returned keys are :data:`_TOKEN_KEYS`, the axes ``pricing.toml`` prices.
    """
    try:
        records: list[dict[str, Any]] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
    except OSError as e:
        _l.debug("cost: unreadable session log %s: %s", path, e)
        return None
    return _claude_session_tokens(records) or _codex_session_tokens(records)


# ---------------------------------------------------------------------------
# LLM per-function facts: trace scan (historical) + structured fields (new runs)
# ---------------------------------------------------------------------------


def _elapsed_stats(values: list[float]) -> dict[str, float]:
    """``mean_s`` / ``median_s`` / ``total_s`` over per-function wall times."""
    return {
        "mean_s": sum(values) / len(values),
        "median_s": statistics.median(values),
        "total_s": sum(values),
    }


def _sum_tokens(per_call: list[dict[str, int]]) -> dict[str, int] | None:
    """Fold per-call token dicts into one entry (+ how many sessions summed)."""
    if not per_call:
        return None
    out = {key: sum(int(tokens.get(key) or 0) for tokens in per_call) for key in _TOKEN_KEYS}
    out["sessions"] = len(per_call)
    return out


def scan_llm_traces(traces_dir: Path) -> dict[str, dict[str, Any]]:
    """Per-backend LLM cost facts from a ``$DECBENCH_LLM_TRACE_DIR`` tree.

    One entry per ``<traces_dir>/<backend>/`` directory holding ``*.md`` traces
    (written by ``llm_dec._save_trace``). FAILED/TIMEOUT calls are *included* in
    the elapsed and token sums — that wall time and those tokens were genuinely
    spent — and counted in ``failed``. Token sums come from the sibling
    ``*.session.jsonl`` files via :func:`parse_session_tokens`; ``tokens`` is
    ``None`` when no session log parsed (an unknown backend's format).
    """
    out: dict[str, dict[str, Any]] = {}
    if not traces_dir.is_dir():
        return out
    for backend_dir in sorted(p for p in traces_dir.iterdir() if p.is_dir()):
        mds = sorted(backend_dir.glob("*.md"))
        if not mds:
            continue
        model: str | None = None
        elapsed: list[float] = []
        failed = 0
        for md in mds:
            try:
                text = md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if model is None and (m := _TRACE_MODEL_RE.search(text)):
                model = m.group("model")
            if (m := _TRACE_STATUS_RE.search(text)) and m.group("status") != "ok":
                failed += 1
            if m := _TRACE_ELAPSED_RE.search(text):
                elapsed.append(float(m.group("secs")))
        per_call = [
            tokens
            for session in sorted(backend_dir.glob("*.session.jsonl"))
            if (tokens := parse_session_tokens(session)) is not None
        ]
        out[backend_dir.name] = {
            "model": model,
            "functions": len(mds),
            "failed": failed,
            "elapsed": _elapsed_stats(elapsed) if elapsed else None,
            "tokens": _sum_tokens(per_call),
        }
    return out


def scan_structured_costs(tree: Path, opt_levels: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Per-backend LLM cost facts from the STRUCTURED per-function fields.

    Runs made after ``FunctionDecompilation.time_seconds`` / ``llm_tokens``
    landed persist them into the decompiled TOMLs' per-function tables
    (``DecompilationResult.to_toml``), which is authoritative — preferred over
    the trace scan by :func:`build_cost_info`. Files without the fields are
    skipped on a cheap substring sniff before the (expensive) full TOML parse,
    so the historical bulk of a tree costs one read each, no parse.
    """
    import toml

    elapsed: dict[str, list[float]] = {}
    tokens: dict[str, list[dict[str, int]]] = {}
    failed: dict[str, int] = {}
    model: dict[str, str | None] = {}

    for path in _decompiled_tomls(tree, opt_levels):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "time_seconds" not in text:
            continue  # no structured fields — the trace scan's territory
        try:
            data = toml.loads(text)
        except Exception:  # noqa: BLE001
            continue
        dec = str(data.get("decompiler") or "")
        if not dec:
            continue
        # The header `version` is "<model> (<cli version>)" for the LLM backends.
        if dec not in model:
            raw = str(data.get("version") or "")
            model[dec] = raw.split(" (")[0] or None
        failed[dec] = failed.get(dec, 0) + len(data.get("failed_functions") or ())
        for key, func in data.items():
            if not key.startswith("functions.") or not isinstance(func, dict):
                continue
            secs = func.get("time_seconds")
            if isinstance(secs, (int, float)):
                elapsed.setdefault(dec, []).append(float(secs))
            per_fn = func.get("llm_tokens")
            if isinstance(per_fn, dict):
                tokens.setdefault(dec, []).append({k: int(v) for k, v in per_fn.items()})

    return {
        dec: {
            "model": model.get(dec),
            "functions": len(elapsed[dec]),
            "failed": failed.get(dec, 0),
            "elapsed": _elapsed_stats(elapsed[dec]),
            "tokens": _sum_tokens(tokens.get(dec, [])),
        }
        for dec in sorted(elapsed)
    }


# ---------------------------------------------------------------------------
# The cost_info blob
# ---------------------------------------------------------------------------


def _discover_opt_levels(tree: Path) -> list[str]:
    """Opt-level dirs of a results tree (those holding a ``*/decompiled/`` dir)."""
    return sorted(d.name for d in tree.iterdir() if d.is_dir() and any(d.glob("*/decompiled")))


def build_cost_info(
    tree: Path,
    traces_dir: Path | None,
    opt_levels: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Assemble ``FunctionData.cost_info`` — facts only, JSON-serializable.

    ``decompile_time`` (batch) may also contain the LLM backends when their
    binaries wrote a normal TOML header; the renderer's ``_cost_block`` lets the
    ``llm`` entry win for such a decompiler, because the per-function timing is
    the honest number for one-agent-call-per-function backends (the batch rate
    divides concurrent per-function wall times by the function count).

    ``llm`` merges the historical trace scan with the structured per-function
    fields, structured winning per backend (see the module docstring).

    ``opt_levels`` defaults to the tree's opt-level directories; the driver
    script passes the exact set from ``function_results.json``.
    """
    opts = list(opt_levels) if opt_levels is not None else _discover_opt_levels(tree)
    llm = scan_llm_traces(traces_dir) if traces_dir is not None else {}
    llm.update(scan_structured_costs(tree, opts))  # structured fields are preferred
    return {
        "decompile_time": scan_decompile_times(tree, opts),
        "llm": llm,
    }
