"""Source-side evidence used for type-blind variable correspondence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from decbench.metrics.variable_features import (
    analyze_c_function,
    extract_c_function,
)
from decbench.metrics.variable_match import (
    FunctionEvidence,
    VariableEvidence,
    extract_source_evidence,
)
from decbench.utils.langs import is_cxx_preprocessed, strip_source_ext


@dataclass(frozen=True)
class SourceEvidenceResult:
    """Type-blind source variables plus extraction diagnostics."""

    variables: tuple[VariableEvidence, ...]
    source_path: Path | None
    native_address_variables: int
    usage_variables: int
    error: str | None = None


class PreprocessedSourceContext:
    """Lazily index preprocessed translation units for one binary evaluation."""

    def __init__(self, paths: list[Path] | tuple[Path, ...], binary_name: str) -> None:
        self.paths = tuple(sorted({Path(path).resolve() for path in paths if Path(path).is_file()}))
        self.binary_name = binary_name
        self._texts: dict[Path, str] = {}
        self._functions: dict[tuple[Path, str], str | None] = {}

    def _function(self, path: Path, function_name: str) -> str | None:
        key = (path, function_name)
        if key not in self._functions:
            text = self._texts.get(path)
            if text is None:
                text = path.read_text(errors="replace")
                self._texts[path] = text
            self._functions[key] = extract_c_function(text, function_name)
        return self._functions[key]

    def select(self, function_name: str) -> tuple[Path, str] | None:
        """Return one unambiguous C definition, preferring the binary's own TU."""

        candidates: list[tuple[Path, str]] = []
        preferred: list[tuple[Path, str]] = []
        for path in self.paths:
            if is_cxx_preprocessed(path):
                continue
            code = self._function(path, function_name)
            if code is None:
                continue
            row = (path, code)
            candidates.append(row)
            source_stem = strip_source_ext(path.stem)
            if source_stem == self.binary_name or source_stem.startswith(self.binary_name + "-"):
                preferred.append(row)
        if len(preferred) == 1:
            return preferred[0]
        return candidates[0] if len(candidates) == 1 else None


def build_source_evidence(
    binary_path: Path | None,
    function_name: str,
    function_address: int,
    ground_truth_vars: list[dict[str, Any]],
    context: PreprocessedSourceContext | None,
) -> SourceEvidenceResult:
    """Join DWARF variables to source addresses and type-blind C usage features."""

    selected = context.select(function_name) if context is not None else None
    source_path, source_code = selected if selected is not None else (None, None)
    native: FunctionEvidence | None = None
    error: str | None = None
    if binary_path is not None and source_path is not None:
        try:
            native = extract_source_evidence(
                binary_path,
                source_path,
                function_name,
                preprocessed_path=source_path,
                include_inlined=True,
                function_address=function_address,
                feature_code=source_code,
            )
        except Exception as exc:  # noqa: BLE001 - evidence is a best-effort channel
            error = type(exc).__name__

    native_by_id = (
        {variable.identity: variable for variable in native.variables} if native is not None else {}
    )
    usage = (
        analyze_c_function(
            source_code,
            function_name,
            (str(variable.get("name", "")) for variable in ground_truth_vars),
        )
        if source_code is not None
        else None
    )

    variables: list[VariableEvidence] = []
    for index, variable in enumerate(ground_truth_vars):
        identity = str(variable.get("identity") or f"source:{index}")
        native_variable = native_by_id.get(identity)
        name = str(variable.get("name", ""))
        raw_features = variable.get("usage_features", ())
        if isinstance(raw_features, dict):
            supplied_features = tuple(
                sorted((str(feature), int(count)) for feature, count in raw_features.items())
            )
        else:
            supplied_features = tuple(
                sorted((str(feature), int(count)) for feature, count in raw_features)
            )
        features = (
            usage.features.get(name, supplied_features)
            if usage is not None and name
            else supplied_features
        )
        variables.append(
            VariableEvidence(
                identity=identity,
                name="",
                addresses=(
                    native_variable.addresses
                    if native_variable is not None
                    else frozenset(int(address) for address in variable.get("addresses", []))
                ),
                stack_offsets=tuple(int(value) for value in variable.get("rbp_offset", [])),
                size=None,
                kind="arg" if variable.get("is_arg") else "local",
                arg_index=(
                    int(variable["arg_index"]) if variable.get("arg_index") is not None else None
                ),
                usage_features=features,
            )
        )

    frozen = tuple(replace(variable, name="", size=None) for variable in variables)
    return SourceEvidenceResult(
        frozen,
        source_path,
        sum(bool(variable.addresses) for variable in frozen),
        sum(bool(variable.usage_features) for variable in frozen),
        error,
    )
