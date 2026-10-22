"""Opt-in C++ GED connection diagnostics, separate from default metrics/Union."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from decbench.metrics.ged import GEDMetric
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.models.metrics import MetricResult
from decbench.utils.cfg_identity import (
    NativeSourceIndex,
    SourceCfgIndex,
    decompiled_cfgs,
    native_sources,
)


class CppGedEvaluation(BaseModel):
    """Coverage is explicit; missing CFGs are never silently perfect scores."""

    profile: str = "cpp-ged-origin-v3-diagnostic"
    official_score: bool = False
    requested: int
    compilation_database_sha256: str | None = None
    input_binary_sha256: str
    producer_code_sha256: dict[str, str]
    source_eligible: int
    decompiled_connected: int
    paired: int
    source_statuses: dict[str, int]
    decompiled_statuses: dict[str, int]
    source_evidence: dict[str, dict] = Field(default_factory=dict)
    decompiled_evidence: dict[str, dict] = Field(default_factory=dict)
    source_inputs: list[dict] = Field(default_factory=list)
    bounds: list[str] = Field(
        default_factory=lambda: [
            "Isolated definition CFG; full-TU callee context is not qualified",
            "No template specialization or implicit lifetime/exception-edge qualification",
            "Compilation database is asserted provenance, not independent link qualification",
            "Diagnostic only; no corpus qualification, default GED or Union score",
            "Producer CFG connection does not establish C++ validity; bounded defects reject",
        ]
    )
    metric: MetricResult


def evaluate_cpp_ged(
    decompilation: DecompilationResult,
    preprocessed_sources: list[Path] | None = None,
    *,
    source_index: SourceCfgIndex | None = None,
    native_index: NativeSourceIndex | None = None,
    requested_functions: list[tuple[str, int]] | None = None,
    compilation_database: Path | None = None,
) -> CppGedEvaluation:
    """Join exact native entries, original locations and producer-record CFGs.

    Source CFGs are strictly parsed isolated definitions. Template specialization,
    implicit object/exception effects and full-TU callee context are not qualified
    by this diagnostic profile. It does not alter default GED or its arithmetic.
    """
    if requested_functions is not None:
        addresses = {address for _, address in requested_functions}
        if len(addresses) != len(requested_functions) or any(address < 0 for address in addresses):
            raise ValueError("requested entries must have distinct nonnegative addresses")
        working = decompilation.model_copy(deep=True)
        working.functions = {
            key: f for key, f in working.functions.items() if f.address in addresses
        }
        returned = [f.address for f in working.functions.values()]
        if len(returned) != len(set(returned)):
            raise ValueError("ambiguous producer records at one requested address")
        for name, address in requested_functions:
            if address not in returned:
                working.add_function(
                    FunctionDecompilation(name=name, address=address, decompiled_code="")
                )
        decompilation = working
    if any(path.suffix != ".ii" for path in preprocessed_sources or []):
        raise ValueError("C++ GED diagnostics require preprocessed .ii inputs")
    if native_index is None:
        native_index = native_sources(
            decompilation.binary_path,
            {function.address for function in decompilation.functions.values()},
        )
    if compilation_database is not None:
        native_index = native_index.with_compilation_database(compilation_database)
    native_index.validate(decompilation.binary_path)
    if source_index is None:
        source_index = SourceCfgIndex()
        records = tuple(rows[0] for rows in native_index.values() if len(rows) == 1)
        for path in preprocessed_sources or []:
            data = path.read_bytes()
            source_index.add(data.decode("utf-8", "replace"), str(path), native_records=records)
            source_index.inputs[-1]["sha256"] = hashlib.sha256(data).hexdigest()
    source = source_index.resolve(decompilation, native_index)
    decompiled = decompiled_cfgs(decompilation)
    metric = MetricResult(
        metric_name="cpp_ged_diagnostic",
        decompiler_name=decompilation.decompiler.decompiler_name,
        binary_name=decompilation.binary_name,
    )
    evaluator = GEDMetric()
    for key, function in decompilation.functions.items():
        if key not in source.cfgs or key not in decompiled.cfgs:
            continue
        value = evaluator.compute_for_function(
            function, source_cfg=source.cfgs[key], decompiled_cfg=decompiled.cfgs[key]
        )
        if not math.isfinite(value.value):
            raise RuntimeError(f"GED evaluator failed for {key}: {value.metadata}")
        metric.function_results[key] = value
    metric.compute_aggregates()
    return CppGedEvaluation(
        requested=len(decompilation.functions),
        input_binary_sha256=native_index.binary_sha256,
        compilation_database_sha256=native_index.compilation_database_sha256,
        producer_code_sha256={
            key: hashlib.sha256(f.decompiled_code.encode("utf-8")).hexdigest()
            for key, f in decompilation.functions.items()
        },
        source_eligible=len(source.cfgs),
        decompiled_connected=len(decompiled.cfgs),
        paired=len(source.cfgs.keys() & decompiled.cfgs.keys()),
        source_statuses=dict(Counter(row["status"] for row in source.evidence.values())),
        decompiled_statuses=dict(Counter(row["status"] for row in decompiled.evidence.values())),
        source_evidence=source.evidence,
        decompiled_evidence=decompiled.evidence,
        source_inputs=source_index.inputs,
        metric=metric,
    )
