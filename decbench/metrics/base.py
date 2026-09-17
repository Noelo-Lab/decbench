"""Base metric interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
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

    # Bump this whenever a metric's computation semantics change, or the
    # content-addressed cache will serve values from the older formula.
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

    @staticmethod
    def _cfg_for_function(
        cfgs: dict[str, DiGraph],
        storage_key: str,
        function_name: str,
        name_count: int,
    ) -> DiGraph | None:
        """Resolve a CFG without conflating same-name C++ functions.

        Collision-safe CFG producers can key graphs by the decompilation result's
        storage key (for example ``foo@0x401000``), which always wins.  The
        historical plain-name fallback remains valid only when the function name
        is unique within this binary.  For an overloaded/same-name group, a lone
        ``cfgs['foo']`` is ambiguous and must not be applied to every function.
        """
        exact = cfgs.get(storage_key)
        if exact is not None:
            return exact
        if name_count == 1:
            return cfgs.get(function_name)
        return None

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
        name_counts = Counter(function.name for function in decompilation.functions.values())

        for storage_key, func_decomp in decompilation.functions.items():
            try:
                count = name_counts[func_decomp.name]
                source_cfg = self._cfg_for_function(
                    source_cfgs,
                    storage_key,
                    func_decomp.name,
                    count,
                )
                decompiled_cfg = self._cfg_for_function(
                    decompiled_cfgs,
                    storage_key,
                    func_decomp.name,
                    count,
                )

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
                # A non-finite value means "unmeasurable for everyone". Abstain so it leaves
                # this metric's denominator uniformly instead of counting as a failure.
                if not math.isfinite(value.value):
                    continue
                function_results[storage_key] = value

            except Exception as e:
                errors.append(f"{storage_key}: {str(e)}")

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
