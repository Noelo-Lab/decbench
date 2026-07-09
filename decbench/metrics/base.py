"""Base metric interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from decbench import caching
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

    # Bump when a metric's computation semantics change so stale cache entries
    # from an older code version are never reused. Override per-metric when its
    # specific inputs/formula change.
    cache_version: str = "1"

    def __init__(self, config: MetricConfig | None = None):
        self.config = config or MetricConfig()

    def _cached_value(
        self,
        key_inputs: list[Any],
        compute: Callable[[], MetricValue],
    ) -> MetricValue:
        """Return a metric value, served from the on-disk cache when possible.

        The metric value is a pure function of ``key_inputs`` (plus the metric
        name and :attr:`cache_version`). On a cache hit we reconstruct the
        :class:`MetricValue` from its stored JSON; on a miss we compute it and
        store the result. Caching is a no-op when disabled
        (``DECBENCH_NO_CACHE``) so behavior is byte-identical to no cache.
        """
        if not caching.cache_enabled():
            return compute()

        key = caching.stable_hash(self.name, self.cache_version, *key_inputs)
        cache = caching.get_cache("metric")
        hit = cache.get(key)
        if hit is not None:
            try:
                return MetricValue(**hit)
            except Exception:
                # Corrupt/incompatible cache entry: fall through and recompute.
                pass

        value = compute()
        cache.put(key, value.model_dump(mode="json"))
        return value

    @abstractmethod
    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        **kwargs: Any,
    ) -> MetricValue: ...

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs: dict[str, DiGraph] | None = None,
        decompiled_cfgs: dict[str, DiGraph] | None = None,
        **kwargs: Any,
    ) -> MetricResult:
        """Compute this metric for all functions in a binary."""
        import math
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
                # A non-finite value means "unmeasurable for everyone" (e.g. GED
                # with an empty-prototype/degenerate source CFG). ABSTAIN — don't
                # record it — so it's excluded from this metric's denominator
                # uniformly for all decompilers, rather than counted as a failure.
                if not math.isfinite(value.value):
                    continue
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
