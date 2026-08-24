"""Fail-closed, type-blind variable evidence from an exact final C rendering."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from decbench.models.decompilation import (
    DecompilationResult,
    FunctionDecompilation,
    with_variable_occurrence_policy,
)

FINAL_RENDER_PROVENANCE_KEY = "final_render_variable_provenance"
FINAL_RENDER_PROVENANCE_SCHEMA = "decbench-final-render-variable-provenance-v1"
FROZEN_PHOENIX_VERSION = "9.2.213"


def is_frozen_phoenix_render(result: DecompilationResult) -> bool:
    """Whether a checkpoint carries the audited same-render Phoenix contract."""

    metadata = result.decompiler
    extra = metadata.extra
    return (
        metadata.decompiler_name.partition("@")[0] == "phoenix"
        and metadata.decompiler_version == FROZEN_PHOENIX_VERSION
        and isinstance(extra, Mapping)
        and extra.get("backend") == "angr"
        and extra.get("via") == "raw"
    )


@dataclass
class FinalRenderProvenanceReport:
    """Aggregate evidence added to one in-memory decompilation result."""

    functions_seen: int = 0
    functions_with_valid_line_maps: int = 0
    functions_enriched: int = 0
    variables_seen: int = 0
    variables_with_existing_evidence: int = 0
    variables_with_exact_occurrences: int = 0
    variables_enriched: int = 0
    addresses_attached: int = 0

    def metadata(self, backend: str) -> dict[str, int | str]:
        """Return a stable, non-sensitive summary for result metadata."""

        return {
            "schema": FINAL_RENDER_PROVENANCE_SCHEMA,
            "backend": backend,
            "functions_seen": self.functions_seen,
            "functions_with_valid_line_maps": self.functions_with_valid_line_maps,
            "functions_enriched": self.functions_enriched,
            "variables_seen": self.variables_seen,
            "variables_with_existing_evidence": self.variables_with_existing_evidence,
            "variables_with_exact_occurrences": self.variables_with_exact_occurrences,
            "variables_enriched": self.variables_enriched,
            "addresses_attached": self.addresses_attached,
        }


def _validated_line_addresses(
    function: FunctionDecompilation,
) -> dict[int, frozenset[int]] | None:
    line_count = function.decompiled_code.count("\n") + 1
    output: dict[int, frozenset[int]] = {}
    for mapping in function.line_mappings:
        line = getattr(mapping, "line_number", None)
        addresses = getattr(mapping, "addresses", None)
        if (
            isinstance(line, bool)
            or not isinstance(line, int)
            or not 1 <= line <= line_count
            or line in output
            or not isinstance(addresses, list)
            or not addresses
            or any(
                isinstance(address, bool) or not isinstance(address, int) or address < 0
                for address in addresses
            )
        ):
            return None
        output[line] = frozenset(addresses)
    return output or None


def enrich_final_render_variable_provenance(
    result: DecompilationResult,
) -> FinalRenderProvenanceReport:
    """Join exact final identifiers to already-sanitized native line rows.

    The caller must establish that every line map belongs to the unchanged
    ``decompiled_code`` string in the same result. Variables with ambiguous C
    bindings, parse errors, no mapped occurrence, or existing evidence abstain.
    Source code, source/DWARF variable names, and recovered or ground-truth
    types are not inputs. The established function label is used only to reject
    a mismatched final definition.
    """

    if not is_frozen_phoenix_render(result):
        raise ValueError("final-render recovery requires the frozen Phoenix origin contract")

    from decbench.metrics.variable_features import variable_occurrence_lines

    report = FinalRenderProvenanceReport()
    backend = result.decompiler.decompiler_name
    for function in result.functions.values():
        report.functions_seen += 1
        function.metadata = with_variable_occurrence_policy(function.metadata, "exact")
        line_addresses = _validated_line_addresses(function)
        if line_addresses is None or not function.variables:
            continue
        report.functions_with_valid_line_maps += 1
        report.variables_seen += len(function.variables)
        occurrences = variable_occurrence_lines(
            function.decompiled_code,
            function.name,
            (variable.name for variable in function.variables),
            require_exact_function_name=True,
        )
        function_enriched = False
        for variable in function.variables:
            existing_lines = getattr(variable, "line_numbers", None)
            existing_addresses = getattr(variable, "addresses", None)
            if existing_lines or existing_addresses:
                report.variables_with_existing_evidence += 1
                continue
            lines = occurrences.get(variable.name, ())
            if not lines:
                continue
            report.variables_with_exact_occurrences += 1
            addresses = sorted(
                {address for line in lines for address in line_addresses.get(line, frozenset())}
            )
            if not addresses:
                continue
            variable.line_numbers = list(lines)
            variable.addresses = addresses
            report.variables_enriched += 1
            report.addresses_attached += len(addresses)
            function_enriched = True
        if function_enriched:
            report.functions_enriched += 1

    result.decompiler.extra = {
        **(result.decompiler.extra or {}),
        FINAL_RENDER_PROVENANCE_KEY: report.metadata(backend),
    }
    return report
