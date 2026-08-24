"""Fail-closed validation for native provenance emitted by decompilers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.utils.native_code import FunctionCode, NativeCodeResolver

SANITIZER_METADATA_KEY = "native_provenance_sanitizer"
SANITIZER_SCHEMA = "decbench-native-provenance-sanitizer-v1"

_COUNT_NAMES = (
    "functions_seen",
    "functions_with_address_provenance",
    "functions_resolved",
    "functions_unresolved",
    "functions_modified",
    "line_mapping_rows_seen",
    "line_mapping_rows_dropped",
    "line_mapping_addresses_seen",
    "line_mapping_addresses_dropped",
    "line_mapping_addresses_normalized",
    "line_mapping_address_duplicates_removed",
    "variable_addresses_seen",
    "variable_addresses_dropped",
    "variable_addresses_normalized",
    "variable_address_duplicates_removed",
    "variable_line_numbers_dropped",
)


@dataclass
class _SanitizerReport:
    counts: dict[str, int] = field(default_factory=lambda: {name: 0 for name in _COUNT_NAMES})
    address_drop_reasons: Counter[str] = field(default_factory=Counter)
    function_failure_reasons: Counter[str] = field(default_factory=Counter)

    def increment(self, name: str, amount: int = 1) -> None:
        self.counts[name] += amount

    def record_address_drop(self, reason: str) -> None:
        self.address_drop_reasons[reason] += 1

    def record_function_failure(self, error: BaseException) -> None:
        self.function_failure_reasons[_function_failure_reason(error)] += 1

    def metadata(self, status: str) -> dict[str, Any]:
        return {
            "schema": SANITIZER_SCHEMA,
            "status": status,
            **self.counts,
            "address_drop_reasons": dict(sorted(self.address_drop_reasons.items())),
            "function_failure_reasons": dict(sorted(self.function_failure_reasons.items())),
        }


def _function_failure_reason(error: BaseException) -> str:
    message = str(error)
    if "no DWARF function matches" in message:
        return "dwarf_function_not_found"
    if "ambiguous DWARF function" in message:
        return "dwarf_function_ambiguous"
    if "not a decoded instruction start" in message:
        return "entry_not_instruction_start"
    if "is not executable" in message:
        return "range_not_executable"
    if "no readable DWARF" in message:
        return "dwarf_unavailable"
    if "unrecognized binary format" in message:
        return "binary_format_unrecognized"
    if "unsupported binary format/architecture" in message:
        return "binary_target_unsupported"
    return "validation_error"


def _has_address_provenance(function: FunctionDecompilation) -> bool:
    if function.line_mappings:
        return True
    return any(variable.addresses for variable in function.variables)


def _filter_addresses(
    values: list[int],
    *,
    code: FunctionCode | None,
    count_prefix: str,
    unavailable_reason: str,
    report: _SanitizerReport,
) -> list[int]:
    report.increment(f"{count_prefix}_seen", len(values))
    output: list[int] = []
    accepted: set[int] = set()
    for address in values:
        canonical: int | None = None
        normalized = False
        reason = unavailable_reason
        if code is not None:
            reason = "not_exact_instruction_start"
            if isinstance(address, int) and not isinstance(address, bool) and address >= 0:
                if address in code.instruction_starts:
                    canonical = address
                elif code.thumb and address & 1 and (address & ~1) in code.instruction_starts:
                    canonical = address & ~1
                    normalized = True
        if canonical is None:
            report.increment(f"{count_prefix}_dropped")
            report.record_address_drop(reason)
            continue
        if canonical in accepted:
            report.increment(f"{count_prefix}_dropped")
            report.increment(f"{count_prefix.removesuffix('es')}_duplicates_removed")
            report.record_address_drop(
                "duplicate_after_normalization" if normalized else "duplicate"
            )
            continue
        if normalized:
            report.increment(f"{count_prefix}_normalized")
        accepted.add(canonical)
        output.append(canonical)
    return sorted(output)


def _sanitize_function(
    function: FunctionDecompilation,
    code: FunctionCode | None,
    unavailable_reason: str,
    report: _SanitizerReport,
) -> bool:
    modified = False
    original_mapped_lines = {mapping.line_number for mapping in function.line_mappings}
    sanitized_mappings = []
    report.increment("line_mapping_rows_seen", len(function.line_mappings))
    for mapping in function.line_mappings:
        addresses = _filter_addresses(
            mapping.addresses,
            code=code,
            count_prefix="line_mapping_addresses",
            unavailable_reason=unavailable_reason,
            report=report,
        )
        if not addresses:
            modified = True
            report.increment("line_mapping_rows_dropped")
            continue
        if addresses != mapping.addresses:
            modified = True
            mapping.addresses = addresses
        sanitized_mappings.append(mapping)
    if len(sanitized_mappings) != len(function.line_mappings):
        function.line_mappings = sanitized_mappings

    surviving_mapped_lines = {mapping.line_number for mapping in sanitized_mappings}
    lost_mapped_lines = original_mapped_lines - surviving_mapped_lines
    for variable in function.variables:
        addresses = _filter_addresses(
            variable.addresses,
            code=code,
            count_prefix="variable_addresses",
            unavailable_reason=unavailable_reason,
            report=report,
        )
        if addresses != variable.addresses:
            modified = True
            variable.addresses = addresses
        if lost_mapped_lines:
            lines = [line for line in variable.line_numbers if line not in lost_mapped_lines]
            removed = len(variable.line_numbers) - len(lines)
            if removed:
                modified = True
                report.increment("variable_line_numbers_dropped", removed)
                variable.line_numbers = lines
    return modified


def _store_report(
    result: DecompilationResult,
    report: _SanitizerReport,
    status: str,
) -> dict[str, Any]:
    metadata = report.metadata(status)
    result.decompiler.extra = {
        **(result.decompiler.extra or {}),
        SANITIZER_METADATA_KEY: metadata,
    }
    return metadata


def sanitize_native_provenance(
    result: DecompilationResult,
    binary_path: Path | None = None,
    *,
    defer_unavailable: bool = False,
) -> dict[str, Any]:
    """Validate all native provenance in one result against one binary context.

    A stripped worker may request deferral, which records the unavailable state
    without changing evidence. Every final producer/evaluator boundary must use
    the default strict behavior: unresolved evidence is removed while recovered
    code and variable records remain intact.
    """

    report = _SanitizerReport()
    report.counts["functions_seen"] = len(result.functions)
    candidates = [
        function for function in result.functions.values() if _has_address_provenance(function)
    ]
    report.counts["functions_with_address_provenance"] = len(candidates)
    if not candidates:
        return _store_report(result, report, "no_address_provenance")

    path = Path(binary_path if binary_path is not None else result.binary_path)
    try:
        resolver = NativeCodeResolver(path)
    except Exception as exc:  # noqa: BLE001
        report.record_function_failure(exc)
        report.counts["functions_unresolved"] = len(candidates)
        if defer_unavailable:
            return _store_report(result, report, "deferred")
        for function in candidates:
            if _sanitize_function(
                function,
                None,
                "binary_validation_unavailable",
                report,
            ):
                report.increment("functions_modified")
        return _store_report(result, report, "fail_closed")

    for function in candidates:
        try:
            code = resolver.resolve(function.name, function.address)
        except Exception as exc:  # noqa: BLE001
            report.increment("functions_unresolved")
            report.record_function_failure(exc)
            if _sanitize_function(
                function,
                None,
                "function_validation_unavailable",
                report,
            ):
                report.increment("functions_modified")
            continue
        report.increment("functions_resolved")
        if _sanitize_function(function, code, "", report):
            report.increment("functions_modified")

    unresolved = report.counts["functions_unresolved"]
    dropped = (
        report.counts["line_mapping_addresses_dropped"]
        + report.counts["variable_addresses_dropped"]
        + report.counts["line_mapping_rows_dropped"]
    )
    status = (
        "partial_fail_closed"
        if unresolved
        else "sanitized" if dropped or report.counts["functions_modified"] else "validated"
    )
    return _store_report(result, report, status)
