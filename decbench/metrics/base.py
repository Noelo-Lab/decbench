"""Base metric interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from decbench.models.metrics import (
    AggregationType,
    MetricCategory,
    MetricResult,
    MetricValue,
)

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult, FunctionDecompilation


class MetricConfig(BaseModel):
    """Configuration for a metric."""

    # Timeout per function
    function_timeout_seconds: float = Field(
        default=60.0,
        description="Timeout per function in seconds",
    )

    # Caching
    use_cache: bool = Field(
        default=True,
        description="Whether to use cached values if available",
    )

    # Metric-specific options
    extra_options: dict[str, Any] = Field(
        default_factory=dict,
        description="Metric-specific configuration options",
    )


class Metric(ABC):
    """Abstract base class for metrics.

    To create a new metric:
    1. Subclass this class
    2. Implement the abstract methods
    3. Register with @register_metric decorator

    Example:
        @register_metric("my_metric")
        class MyMetric(Metric):
            name = "my_metric"
            category = MetricCategory.FAITHFUL

            def compute_for_function(self, decompiled, source_cfg, decompiled_cfg):
                ...
    """

    # Class attributes to be overridden
    name: str = "base"
    display_name: str = "Base Metric"
    description: str = ""
    category: MetricCategory = MetricCategory.FAITHFUL

    # Scoring configuration
    weight: float = 1.0
    lower_is_better: bool = True
    perfect_value: float = 0.0
    default_aggregation: AggregationType = AggregationType.MEAN

    # Whether this metric requires CFGs
    requires_source_cfg: bool = False
    requires_decompiled_cfg: bool = False

    def __init__(self, config: MetricConfig | None = None):
        """Initialize the metric.

        Args:
            config: Configuration for the metric
        """
        self.config = config or MetricConfig()

    @abstractmethod
    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs,
    ) -> MetricValue:
        """Compute this metric for a single function.

        Args:
            decompiled: The decompiled function
            source_cfg: CFG from source code (if requires_source_cfg)
            decompiled_cfg: CFG from decompiled code (if requires_decompiled_cfg)
            **kwargs: Additional metric-specific arguments

        Returns:
            MetricValue with the computed value
        """
        ...

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs: dict[str, DiGraph] | None = None,
        decompiled_cfgs: dict[str, DiGraph] | None = None,
        **kwargs,
    ) -> MetricResult:
        """Compute this metric for all functions in a binary.

        Default implementation iterates over functions.
        Override for more efficient batch computation.

        Args:
            decompilation: Decompilation result for the binary
            source_cfgs: Source CFGs keyed by function name
            decompiled_cfgs: Decompiled CFGs keyed by function name
            **kwargs: Additional metric-specific arguments

        Returns:
            MetricResult with per-function values and aggregates
        """
        import time

        start_time = time.time()
        function_results: dict[str, MetricValue] = {}
        errors: list[str] = []

        source_cfgs = source_cfgs or {}
        decompiled_cfgs = decompiled_cfgs or {}

        for func_name, func_decomp in decompilation.functions.items():
            try:
                source_cfg = source_cfgs.get(func_name)
                decompiled_cfg = decompiled_cfgs.get(func_name)

                # Skip if CFG required but not available
                if self.requires_source_cfg and source_cfg is None:
                    continue
                if self.requires_decompiled_cfg and decompiled_cfg is None:
                    continue

                value = self.compute_for_function(
                    func_decomp,
                    source_cfg=source_cfg,
                    decompiled_cfg=decompiled_cfg,
                    **kwargs,
                )
                function_results[func_name] = value

            except Exception as e:
                errors.append(f"{func_name}: {str(e)}")

        result = MetricResult(
            metric_name=self.name,
            decompiler_name=decompilation.decompiler.decompiler_name,
            binary_name=decompilation.binary_name,
            function_results=function_results,
            computation_time_seconds=time.time() - start_time,
            errors=errors,
        )

        # Compute aggregates
        result.compute_aggregates(perfect_value=self.perfect_value)

        return result

    def normalize_value(self, value: float, normalizer: float) -> float:
        """Normalize a metric value.

        Default implementation divides by normalizer.
        Override for custom normalization.

        Args:
            value: Raw metric value
            normalizer: Value to normalize by

        Returns:
            Normalized value
        """
        if normalizer == 0:
            return 0.0
        return value / normalizer

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, category={self.category.value!r})"
