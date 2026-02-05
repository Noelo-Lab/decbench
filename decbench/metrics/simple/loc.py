"""Lines of code and simplicity metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricCategory, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import FunctionDecompilation


@register_metric("loc")
class LOCMetric(Metric):
    """Lines of Code metric.

    Counts the number of lines in decompiled code.
    Lower is generally better for readability.
    """

    name = "loc"
    display_name = "Lines of Code"
    description = "Number of lines in decompiled code"
    category = MetricCategory.SIMPLE

    weight = 1.0
    lower_is_better = True
    perfect_value = 0.0  # Relative to source, but we track raw value
    default_aggregation = AggregationType.MEAN

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Compute LOC for a function."""
        code = decompiled.decompiled_code

        # Count non-empty lines
        lines = [line for line in code.split("\n") if line.strip()]
        loc = len(lines)

        # Also count blank lines for context
        total_lines = code.count("\n") + 1

        return MetricValue(
            value=float(loc),
            raw_value=loc,
            metadata={
                "total_lines": total_lines,
                "blank_lines": total_lines - loc,
            },
        )


@register_metric("gotos")
class GotoMetric(Metric):
    """Goto statement count metric.

    Counts goto statements in decompiled code.
    Fewer gotos indicate better structured code.
    """

    name = "gotos"
    display_name = "Goto Count"
    description = "Number of goto statements in decompiled code"
    category = MetricCategory.SIMPLE

    weight = 0.8
    lower_is_better = True
    perfect_value = 0.0
    default_aggregation = AggregationType.SUM

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Count gotos in a function."""
        # Check metadata first (may be pre-computed)
        if "gotos" in decompiled.metadata:
            goto_count = decompiled.metadata["gotos"]
        else:
            # Count manually
            code = decompiled.decompiled_code
            goto_count = code.count("goto ")

        return MetricValue(
            value=float(goto_count),
            raw_value=goto_count,
            metadata={
                "has_gotos": goto_count > 0,
            },
        )


@register_metric("cyclomatic_complexity")
class CyclomaticComplexityMetric(Metric):
    """Cyclomatic Complexity metric.

    Computed from CFG as: E - N + 2
    where E = edges, N = nodes.

    Lower complexity indicates simpler code.
    """

    name = "cyclomatic_complexity"
    display_name = "Cyclomatic Complexity"
    description = "Code complexity based on CFG structure"
    category = MetricCategory.SIMPLE

    weight = 0.5
    lower_is_better = True
    perfect_value = 1.0  # Minimum complexity
    default_aggregation = AggregationType.MEAN

    requires_source_cfg = False
    requires_decompiled_cfg = True

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Compute cyclomatic complexity."""
        if decompiled_cfg is None:
            # Fall back to estimation from code
            return self._estimate_from_code(decompiled)

        nodes = decompiled_cfg.number_of_nodes()
        edges = decompiled_cfg.number_of_edges()

        # CC = E - N + 2 (for single component)
        cc = edges - nodes + 2

        return MetricValue(
            value=float(max(1, cc)),  # Minimum of 1
            raw_value=cc,
            metadata={
                "nodes": nodes,
                "edges": edges,
            },
        )

    def _estimate_from_code(
        self,
        decompiled: FunctionDecompilation,
    ) -> MetricValue:
        """Estimate CC from code when CFG not available."""
        code = decompiled.decompiled_code

        # Count decision points
        decision_keywords = [
            "if", "else if", "while", "for", "case", "&&", "||", "?"
        ]
        decisions = 0
        for kw in decision_keywords:
            decisions += code.count(f" {kw} ") + code.count(f" {kw}(")

        cc = decisions + 1  # Base complexity of 1

        return MetricValue(
            value=float(cc),
            raw_value=cc,
            metadata={
                "estimated": True,
                "decisions": decisions,
            },
        )


@register_metric("bool_ops")
class BooleanOperationsMetric(Metric):
    """Boolean operations count metric.

    Counts && and || operators.
    Many boolean ops can indicate complex conditions.
    """

    name = "bool_ops"
    display_name = "Boolean Operations"
    description = "Count of && and || operators"
    category = MetricCategory.SIMPLE

    weight = 0.3
    lower_is_better = True
    perfect_value = 0.0
    default_aggregation = AggregationType.SUM

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Count boolean operations."""
        # Check metadata first
        if "bools" in decompiled.metadata:
            bool_count = decompiled.metadata["bools"]
        else:
            code = decompiled.decompiled_code
            and_count = code.count(" && ")
            or_count = code.count(" || ")
            bool_count = and_count + or_count

        return MetricValue(
            value=float(bool_count),
            raw_value=bool_count,
            metadata={},
        )
