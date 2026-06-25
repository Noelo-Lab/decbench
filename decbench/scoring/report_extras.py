"""Builders for the HTML report's v2 extras: hardest functions and history.

These are pure functions consumed by the WEB cluster's renderer
(``decbench/rendering/html.py``). They turn the pipeline's nested evaluation /
decompilation results into the bounded, code-carrying ``HardestEntry`` list and
the ``HistoryPoint`` list embedded in :class:`FunctionData`.

Design goals:
- Pure & defensive. ``attach_extras`` must never raise (each section is wrapped
  in try/except), so a malformed corner of the results never sinks a report.
- Read decompiled code from
  ``decompile_results[proj][opt_level][binary][dec].functions[fn].decompiled_code``.
- "Worst" = farthest from the metric's ``perfect_value`` (pulled from the
  :class:`MetricRegistry`).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from decbench.models.function_data import HardestEntry, HistoryPoint

if TYPE_CHECKING:
    from decbench.models.function_data import FunctionData
    from decbench.models.metrics import MetricResult
    from decbench.models.project import OptimizationLevel, Project


def _perfect_value_for(metric_name: str) -> float:
    """Return a metric's perfect value, tolerating an unregistered metric."""
    try:
        from decbench.metrics.registry import MetricRegistry

        return MetricRegistry.get(metric_name).perfect_value
    except Exception:
        return 0.0


def _opt_value(opt_level: Any) -> str:
    """Normalize an OptimizationLevel enum (or string) to its string value."""
    return opt_level.value if hasattr(opt_level, "value") else str(opt_level)


def _lookup_decompiled(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
    dec_name: str,
    func_name: str,
) -> str | None:
    """Best-effort lookup of decompiled C for one function.

    ``decompile_results`` is ``proj -> OptimizationLevel -> binary -> dec ->
    DecompilationResult``. The opt-level key may be an enum or a string, so we
    try both.
    """
    if not decompile_results:
        return None
    try:
        opt_results = decompile_results.get(project)
        if not opt_results:
            return None
        binary_results = opt_results.get(opt_level)
        if binary_results is None:
            # Fall back to matching by string value of the opt key.
            ov = _opt_value(opt_level)
            for key, val in opt_results.items():
                if _opt_value(key) == ov:
                    binary_results = val
                    break
        if not binary_results:
            return None
        dec_results = binary_results.get(binary)
        if not dec_results:
            return None
        dec_result = dec_results.get(dec_name)
        if dec_result is None:
            return None
        func = dec_result.functions.get(func_name)
        if func is None:
            return None
        return func.decompiled_code
    except Exception:
        return None


def _lookup_line_count(
    decompile_results: Any,
    project: str,
    opt_level: Any,
    binary: str,
    dec_name: str,
    func_name: str,
) -> int | None:
    """Best-effort decompiled line count for one function (the 'size')."""
    if not decompile_results:
        return None
    try:
        opt_results = decompile_results.get(project) or {}
        binary_results = opt_results.get(opt_level)
        if binary_results is None:
            ov = _opt_value(opt_level)
            for key, val in opt_results.items():
                if _opt_value(key) == ov:
                    binary_results = val
                    break
        if not binary_results:
            return None
        dec_result = (binary_results.get(binary) or {}).get(dec_name)
        if dec_result is None:
            return None
        func = dec_result.functions.get(func_name)
        if func is None:
            return None
        return func.line_count
    except Exception:
        return None


def build_hardest(
    evaluation_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]],
    ],
    decompile_results: Any,
    projects: list[Project] | None = None,
    per_metric_per_dec: int = 15,
) -> list[HardestEntry]:
    """Pick the worst N functions per (metric, decompiler).

    "Worst" = the largest absolute distance from the metric's ``perfect_value``.
    Only functions that have decompiled code are included (no code → skipped).

    Args:
        evaluation_results: Nested
            ``project -> OptimizationLevel -> binary -> decompiler -> metric ->
            MetricResult`` mapping, where ``MetricResult.function_results`` maps
            function name to a ``MetricValue`` (with ``.value``).
        decompile_results: Nested decompilation results used to pull the
            decompiled (and best-effort source) code for each entry.
        projects: Unused today (reserved for source-code lookups); accepted so
            callers can pass it uniformly.
        per_metric_per_dec: How many worst functions to keep for each
            (metric, decompiler) pair.

    Returns:
        A flat list of :class:`HardestEntry`, grouped implicitly by
        (metric, decompiler) and ordered worst-first within each group.
    """
    # (metric, dec) -> list of candidate dicts
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    perfect_cache: dict[str, float] = {}

    for project, opt_results in (evaluation_results or {}).items():
        for opt_level, binary_results in (opt_results or {}).items():
            opt_str = _opt_value(opt_level)
            for binary, dec_results in (binary_results or {}).items():
                for dec_name, metric_results in (dec_results or {}).items():
                    for metric_name, result in (metric_results or {}).items():
                        if metric_name not in perfect_cache:
                            perfect_cache[metric_name] = _perfect_value_for(
                                metric_name
                            )
                        perfect = perfect_cache[metric_name]
                        fr = getattr(result, "function_results", None) or {}
                        for func_name, mv in fr.items():
                            try:
                                value = float(mv.value)
                            except Exception:
                                continue
                            distance = abs(value - perfect)
                            if distance == 0.0:
                                continue  # perfect ⇒ not "hard"
                            buckets.setdefault((metric_name, dec_name), []).append(
                                {
                                    "metric": metric_name,
                                    "decompiler": dec_name,
                                    "project": project,
                                    "opt_level": opt_str,
                                    "opt_key": opt_level,
                                    "binary": binary,
                                    "function": func_name,
                                    "value": value,
                                    "perfect_value": perfect,
                                    "distance": distance,
                                }
                            )

    entries: list[HardestEntry] = []
    for (metric_name, dec_name), candidates in buckets.items():
        # Worst first: farthest from perfect, then larger raw value as tiebreak.
        candidates.sort(key=lambda c: (c["distance"], c["value"]), reverse=True)
        kept = 0
        for c in candidates:
            if kept >= per_metric_per_dec:
                break
            code = _lookup_decompiled(
                decompile_results,
                c["project"],
                c["opt_key"],
                c["binary"],
                dec_name,
                c["function"],
            )
            if not code:
                continue  # require code to be worth showing
            size = _lookup_line_count(
                decompile_results,
                c["project"],
                c["opt_key"],
                c["binary"],
                dec_name,
                c["function"],
            )
            entries.append(
                HardestEntry(
                    metric=metric_name,
                    decompiler=dec_name,
                    project=c["project"],
                    opt_level=c["opt_level"],
                    binary=c["binary"],
                    function=c["function"],
                    value=c["value"],
                    perfect_value=c["perfect_value"],
                    size=size,
                    labels=[],
                    decompiled_code=code,
                    source_code=None,
                )
            )
            kept += 1

    return entries


def build_history(
    history_inputs: Iterable[Any] | None,
) -> list[HistoryPoint]:
    """Build ``HistoryPoint`` records from loosely-typed inputs.

    Accepts an iterable of either:
    - dicts with keys ``decompiler``, ``version``, optional ``date``,
      ``scores`` (metric -> pct), ``overall``; or
    - tuples/lists ``(decompiler, version, date, scores, overall)`` (trailing
      items optional).

    Anything that can't be coerced is skipped. The lead supplies inputs.
    """
    points: list[HistoryPoint] = []
    if not history_inputs:
        return points

    for item in history_inputs:
        try:
            if isinstance(item, HistoryPoint):
                points.append(item)
                continue
            if isinstance(item, dict):
                decompiler = item.get("decompiler")
                version = item.get("version")
                if decompiler is None or version is None:
                    continue
                points.append(
                    HistoryPoint(
                        decompiler=str(decompiler),
                        version=str(version),
                        date=item.get("date"),
                        scores={
                            str(k): float(v)
                            for k, v in (item.get("scores") or {}).items()
                        },
                        overall=float(item.get("overall", 0.0) or 0.0),
                    )
                )
                continue
            # Tuple / list form.
            seq = list(item)
            if len(seq) < 2:
                continue
            decompiler = seq[0]
            version = seq[1]
            date = seq[2] if len(seq) > 2 else None
            scores = seq[3] if len(seq) > 3 else {}
            overall = seq[4] if len(seq) > 4 else 0.0
            points.append(
                HistoryPoint(
                    decompiler=str(decompiler),
                    version=str(version),
                    date=str(date) if date is not None else None,
                    scores={str(k): float(v) for k, v in (scores or {}).items()},
                    overall=float(overall or 0.0),
                )
            )
        except Exception:
            continue

    return points


def attach_extras(
    function_data: FunctionData,
    *,
    evaluation_results: Any,
    decompile_results: Any,
    projects: list[Project] | None = None,
    history_inputs: Iterable[Any] | None = None,
    per_metric_per_dec: int = 15,
) -> FunctionData:
    """Populate ``function_data.hardest`` (and ``history`` if inputs given).

    Tolerant of missing/malformed pieces: each section is wrapped so a failure
    in one never propagates. Returns the same ``function_data`` for chaining.
    """
    try:
        function_data.hardest = build_hardest(
            evaluation_results,
            decompile_results,
            projects,
            per_metric_per_dec=per_metric_per_dec,
        )
    except Exception:
        function_data.hardest = []

    if history_inputs is not None:
        try:
            function_data.history = build_history(history_inputs)
        except Exception:
            function_data.history = []

    return function_data
