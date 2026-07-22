"""Builds :class:`FunctionData` from evaluation and decompilation results."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from decbench.metrics.registry import MetricRegistry
from decbench.models.function_data import BinaryGroup, FunctionData, FunctionRecord
from decbench.scoring.labels import (
    DEFAULT_LARGE_LINE_THRESHOLD,
    binary_labels_for,
    function_labels_for,
)

if TYPE_CHECKING:
    from decbench.models.decompilation import DecompilationResult
    from decbench.models.metrics import MetricResult
    from decbench.models.project import OptimizationLevel, Project


# Placeholder names a decompiler assigns to an address it could not resolve to a
# real symbol (stripped binary). A universe row under such a name is a PHANTOM:
# either a non-source function pulled in by a narrow-to-source miss, or a real
# source function whose address failed to relabel (ARM Thumb T-bit / PE
# ImageBase). Once _relabel_to_dwarf has run (with the Thumb + PE fixes), any
# name still matching this and scoring NO metric for anyone is genuinely
# non-source and must not become its own universe key that every other
# decompiler is marked "failed" on.
_UNRESOLVED_NAME = re.compile(r"^(sub|FUN|fcn|loc|nullsub|unk|off|byte|word|dword|j)_[0-9a-fA-F]+$")


def _is_unresolved_name(name: str) -> bool:
    return bool(_UNRESOLVED_NAME.match(name))


def _with_decompile_cells(evaluation_results: dict, decompile_results: dict | None) -> dict:
    """Return ``evaluation_results`` augmented with an empty eval cell for every
    (project, opt, binary) that was decompiled but has no eval section.

    Keeps the universe (decompile-derived) intact for binaries whose inline
    metrics were skipped (a DECOMPILE_ONLY re-decompile) or otherwise absent, so
    they are not dropped from the dataset. Builds new outer dicts; the inner
    ``dec -> {metric: result}`` mappings are shared by reference (never mutated).
    """
    if not decompile_results:
        return evaluation_results
    merged: dict = {
        proj: {opt: dict(bins) for opt, bins in opts.items()}
        for proj, opts in evaluation_results.items()
    }
    for proj, opts in decompile_results.items():
        m_opts = merged.setdefault(proj, {})
        for opt, bins in opts.items():
            m_bins = m_opts.setdefault(opt, {})
            for binary_name in bins:
                m_bins.setdefault(binary_name, {})
    return merged


def _perfect_value_for(metric_name: str) -> float:
    """Return the perfect value for a metric, mirroring aggregator fallback."""
    try:
        return MetricRegistry.get(metric_name).perfect_value
    except KeyError:
        return 0.0


def _distance_for(metric_name: str, value: object) -> float | None:
    """Raw edit distance to perfect for the report's 'distance' view (or None).

    GED = the graph edit distance itself; type_match = type-flips to exact
    (fp+fn); byte_match = number of changed assembly lines (``changed_lines``).
    """
    import math

    md = getattr(value, "metadata", None) or {}
    v = getattr(value, "value", None)
    if metric_name == "ged":
        return float(v) if isinstance(v, (int, float)) and math.isfinite(v) else None
    if metric_name == "type_match":
        if "fp" in md and "fn" in md:
            return float(int(md["fp"]) + int(md["fn"]))
        return None
    if metric_name == "byte_match":
        cl = md.get("changed_lines")
        return float(cl) if cl is not None else None
    return None


def _line_count_for(
    decompile_results,
    project_name: str,
    opt_level: OptimizationLevel,
    binary_name: str,
    func_name: str,
) -> int | None:
    """Return the line count for a function from any decompiler that has it."""
    if not decompile_results:
        return None

    opt_results = decompile_results.get(project_name)
    if not opt_results:
        return None
    binary_results = opt_results.get(opt_level)
    if not binary_results:
        return None
    dec_results = binary_results.get(binary_name)
    if not dec_results:
        return None

    for dec_result in dec_results.values():
        func = dec_result.functions.get(func_name)
        if func is not None:
            return func.line_count
    return None


def _dec_results_for(
    decompile_results,
    project_name: str,
    opt_level: OptimizationLevel,
    binary_name: str,
) -> dict:
    """Return ``{decompiler: DecompilationResult}`` for one binary (or {})."""
    if not decompile_results:
        return {}
    opt_results = decompile_results.get(project_name) or {}
    binary_results = opt_results.get(opt_level)
    if binary_results is None:
        ov = opt_level.value if hasattr(opt_level, "value") else str(opt_level)
        for k, v in opt_results.items():
            if (k.value if hasattr(k, "value") else str(k)) == ov:
                binary_results = v
                break
    if not binary_results:
        return {}
    return binary_results.get(binary_name) or {}


def build_function_data(
    evaluation_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]],
    ],
    projects: list[Project],
    decompile_results: (
        dict[
            str,
            dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]],
        ]
        | None
    ) = None,
    large_threshold: int = DEFAULT_LARGE_LINE_THRESHOLD,
) -> FunctionData:
    """Build a :class:`FunctionData` dataset from pipeline results.

    Args:
        evaluation_results: Nested mapping
            project -> opt -> binary -> decompiler -> metric -> MetricResult.
        projects: Project objects (used for label configuration).
        decompile_results: Optional decompilation results, used to look up
            per-function line counts for auto labels.
        large_threshold: Line count threshold for the "large" auto label.

    Returns:
        A populated :class:`FunctionData` instance.
    """
    projects_by_name = {p.name: p for p in projects}

    # The universe (which functions each decompiler produced) must be built even
    # for a (project, opt, binary) that has NO eval section — e.g. a
    # DECOMPILE_ONLY re-decompile whose inline metrics were skipped, to be layered
    # back by the reeval scripts. Without this, such a binary/project is driven
    # only by evaluation_results below and silently vanishes from the dataset
    # (the historical "coreutils dropped" bug). Add empty eval cells for every
    # decompiled binary so the loop reaches its decompile-derived universe.
    evaluation_results = _with_decompile_cells(evaluation_results, decompile_results)

    decompilers_seen: set[str] = set()
    metrics_seen: set[str] = set()
    perfect_values: dict[str, float] = {}
    decompiler_versions: dict[str, str] = {}
    groups: list[BinaryGroup] = []

    for project_name, opt_results in evaluation_results.items():
        project = projects_by_name.get(project_name)

        for opt_level, binary_results in opt_results.items():
            opt_value = opt_level.value if hasattr(opt_level, "value") else str(opt_level)

            for binary_name, dec_results in binary_results.items():
                # records keyed by function name for this binary
                records: dict[str, FunctionRecord] = {}
                func_order: list[str] = []

                for dec_name, metric_results in dec_results.items():
                    decompilers_seen.add(dec_name)

                    for metric_name, result in metric_results.items():
                        metrics_seen.add(metric_name)
                        perfect_value = _perfect_value_for(metric_name)
                        perfect_values[metric_name] = perfect_value

                        for func_name, value in result.function_results.items():
                            if func_name not in records:
                                records[func_name] = FunctionRecord(function=func_name)
                                func_order.append(func_name)
                            record = records[func_name]

                            record.values.setdefault(dec_name, {})[metric_name] = value.value
                            record.perfects.setdefault(dec_name, {})[metric_name] = (
                                value.value == perfect_value
                            )
                            dist = _distance_for(metric_name, value)
                            if dist is not None:
                                record.distances.setdefault(dec_name, {})[metric_name] = dist

                # --- Decompile success/failure universe --------------------
                # Record, per (function, decompiler), whether the decompiler
                # actually produced output. The universe is every name any
                # decompiler decompiled (plus explicit failures); a decompiler
                # that didn't produce a universe function "errored" on it (failed
                # or timed out). This makes a decompiler's metric denominator =
                # the set it decompiled — one denominator across all metrics — and
                # powers the Errors column + the normalize-failures view.
                dec_map = _dec_results_for(decompile_results, project_name, opt_level, binary_name)
                allfail_decs: set[str] = set()
                for dec_name, dr in dec_map.items():
                    decompilers_seen.add(dec_name)
                    ver = getattr(dr.decompiler, "decompiler_version", None)
                    if ver:
                        decompiler_versions[dec_name] = str(ver)
                    ff = list(getattr(dr.decompiler, "failed_functions", []) or [])
                    if ff == ["all"]:
                        allfail_decs.add(dec_name)
                    names = list(dr.functions.keys()) + [f for f in ff if f != "all"]
                    for fn in names:
                        if fn not in records:
                            # Don't mint a phantom universe row for an unresolved
                            # placeholder name that scored no metric for anyone
                            # (records already holds everything that scored a
                            # metric, since the metric loop above ran first).
                            # These are non-source functions (narrow miss) or
                            # unrelabeled addresses; a real source function is
                            # relabeled to its DWARF name before this point.
                            if _is_unresolved_name(fn):
                                continue
                            records[fn] = FunctionRecord(function=fn)
                            func_order.append(fn)
                for fn in func_order:
                    rec = records[fn]
                    for dec_name, dr in dec_map.items():
                        ok = (dec_name not in allfail_decs) and (fn in dr.functions)
                        meta = dr.decompiler
                        if (
                            (meta.extra or {}).get("slice_scoped")
                            and not ok
                            and dec_name not in rec.values
                            and fn not in (meta.failed_functions or [])
                        ):
                            # Slice-scoped backend (LLM sample-set) never
                            # attempted this function: no flag at all, not False.
                            continue
                        # a computed metric implies the function was decompiled
                        rec.decompiled[dec_name] = bool(ok or dec_name in rec.values)

                if project is not None:
                    bin_labels = binary_labels_for(project.config, opt_value, binary_name)
                else:
                    bin_labels = list(_opt_only_labels(opt_value))

                # Assign function labels (inherit binary labels + auto labels)
                for func_name in func_order:
                    line_count = _line_count_for(
                        decompile_results,
                        project_name,
                        opt_level,
                        binary_name,
                        func_name,
                    )
                    records[func_name].size = line_count
                    records[func_name].labels = function_labels_for(
                        bin_labels, line_count, large_threshold
                    )

                groups.append(
                    BinaryGroup(
                        project=project_name,
                        opt_level=opt_value,
                        binary=binary_name,
                        labels=bin_labels,
                        functions=[records[name] for name in func_order],
                    )
                )

    return FunctionData(
        schema_version=2,
        decompilers=sorted(decompilers_seen),
        decompiler_versions=decompiler_versions,
        metrics=sorted(metrics_seen),
        perfect_values=perfect_values,
        groups=groups,
    )


def _opt_only_labels(opt_value: str) -> list[str]:
    """Fallback labels when no project config is available."""
    from decbench.scoring.labels import opt_level_labels

    return opt_level_labels(opt_value)
