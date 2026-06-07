"""Builds :class:`FunctionData` from evaluation and decompilation results."""

from __future__ import annotations

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


def _perfect_value_for(metric_name: str) -> float:
    """Return the perfect value for a metric, mirroring aggregator fallback."""
    try:
        return MetricRegistry.get(metric_name).perfect_value
    except KeyError:
        return 0.0


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


def build_function_data(
    evaluation_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, dict[str, MetricResult]]]],
    ],
    projects: list[Project],
    decompile_results: dict[
        str,
        dict[OptimizationLevel, dict[str, dict[str, DecompilationResult]]],
    ]
    | None = None,
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

    decompilers_seen: set[str] = set()
    metrics_seen: set[str] = set()
    perfect_values: dict[str, float] = {}
    groups: list[BinaryGroup] = []

    for project_name, opt_results in evaluation_results.items():
        project = projects_by_name.get(project_name)

        for opt_level, binary_results in opt_results.items():
            opt_value = (
                opt_level.value if hasattr(opt_level, "value") else str(opt_level)
            )

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
                                records[func_name] = FunctionRecord(
                                    function=func_name
                                )
                                func_order.append(func_name)
                            record = records[func_name]

                            record.values.setdefault(dec_name, {})[metric_name] = (
                                value.value
                            )
                            record.perfects.setdefault(dec_name, {})[metric_name] = (
                                value.value == perfect_value
                            )

                if project is not None:
                    bin_labels = binary_labels_for(
                        project.config, opt_value, binary_name
                    )
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
        schema_version=1,
        decompilers=sorted(decompilers_seen),
        metrics=sorted(metrics_seen),
        perfect_values=perfect_values,
        groups=groups,
    )


def _opt_only_labels(opt_value: str) -> list[str]:
    """Fallback labels when no project config is available."""
    from decbench.scoring.labels import opt_level_labels

    return opt_level_labels(opt_value)
