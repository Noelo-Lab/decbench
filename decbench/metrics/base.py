"""Base metric interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from decbench.models.metrics import (
    AggregationType,
    MetricResult,
    MetricValue,
)

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult, FunctionDecompilation


class MetricConfig(BaseModel):
    """Configuration for a metric."""

    function_timeout_seconds: float = Field(default=60.0)
    use_cache: bool = Field(default=True)
    extra_options: dict[str, Any] = Field(default_factory=dict)


class Metric(ABC):
    """Abstract base class for metrics.

    To create a new metric:
    1. Subclass this class
    2. Implement compute_for_function
    3. Register with @register_metric decorator
    """

    name: str = "base"
    display_name: str = "Base Metric"
    description: str = ""

    weight: float = 1.0
    lower_is_better: bool = True
    perfect_value: float = 0.0
    default_aggregation: AggregationType = AggregationType.MEAN

    requires_source_cfg: bool = False
    requires_decompiled_cfg: bool = False

    def __init__(self, config: MetricConfig | None = None):
        self.config = config or MetricConfig()

    @abstractmethod
    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs: Any,
    ) -> MetricValue:
        ...

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs: dict[str, DiGraph] | None = None,
        decompiled_cfgs: dict[str, DiGraph] | None = None,
        **kwargs: Any,
    ) -> MetricResult:
        """Compute this metric for all functions in a binary."""
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

        result.compute_aggregates(perfect_value=self.perfect_value)

        return result

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
