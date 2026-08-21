"""Source-side evidence used for type-blind variable correspondence."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from decbench.metrics.variable_features import analyze_c_function, index_c_functions
from decbench.metrics.variable_match import (
    FunctionEvidence,
    SourceBinaryEvidenceContext,
    VariableEvidence,
    _die_ranges,
    extract_source_evidence,
    load_source_lines,
    open_source_binary_context,
)
from decbench.utils.binfmt import die_str_attr
from decbench.utils.langs import is_cxx_preprocessed, strip_source_ext


@dataclass(frozen=True)
class SourceEvidenceResult:
    """Type-blind source variables plus extraction diagnostics."""

    variables: tuple[VariableEvidence, ...]
    source_path: Path | None
    native_address_variables: int
    usage_variables: int
    error: str | None = None


@dataclass(frozen=True)
class _SourceSelection:
    path: Path | None
    function_code: str | None
    errors: tuple[str, ...] = ()


def _decode_path(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _normalized_source_path(path: str, comp_dir: str = "") -> str:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
    comp = PurePosixPath(comp_dir.replace("\\", "/")).as_posix() if comp_dir else ""
    if comp and (normalized == comp or normalized.startswith(comp.rstrip("/") + "/")):
        normalized = normalized[len(comp.rstrip("/")) :].lstrip("/")
    return normalized.removeprefix("./")


def _line_file_path(line_program: Any, index: int, comp_dir: str) -> str:
    entries = line_program.header["file_entry"]
    if not 0 <= index < len(entries):
        return ""
    entry = entries[index]
    name = _decode_path(entry.name)
    if PurePosixPath(name).is_absolute():
        return _normalized_source_path(name, comp_dir)
    directory = ""
    dir_index = int(getattr(entry, "dir_index", 0))
    directories = line_program.header["include_directory"]
    version = int(line_program.header.get("version", 4))
    actual = dir_index if version >= 5 else dir_index - 1
    if 0 <= actual < len(directories):
        directory = _decode_path(directories[actual])
    joined = PurePosixPath(directory, name).as_posix() if directory else name
    return _normalized_source_path(joined, comp_dir)


def _cu_source_path(cu: Any, line_program: Any) -> str:
    top = cu.get_top_DIE()
    name_attr = top.attributes.get("DW_AT_name")
    comp_attr = top.attributes.get("DW_AT_comp_dir")
    comp_dir = _decode_path(comp_attr.value) if comp_attr is not None else ""
    dwarf_name = (
        _normalized_source_path(_decode_path(name_attr.value), comp_dir)
        if name_attr is not None
        else ""
    )
    line_name = _line_file_path(line_program, 0, comp_dir)
    qualified = [path for path in (dwarf_name, line_name) if len(PurePosixPath(path).parts) >= 2]
    if dwarf_name and len(PurePosixPath(dwarf_name).parts) >= 2:
        return dwarf_name
    if qualified:
        return qualified[0]
    return dwarf_name or line_name


def _path_has_suffix(candidate: str, suffix: str) -> bool:
    candidate_parts = PurePosixPath(_normalized_source_path(candidate)).parts
    suffix_parts = PurePosixPath(_normalized_source_path(suffix)).parts
    return bool(suffix_parts) and candidate_parts[-len(suffix_parts) :] == suffix_parts


class PreprocessedSourceContext:
    """Index preprocessed translation units and address-pinned DWARF CUs once."""

    def __init__(self, paths: list[Path] | tuple[Path, ...], binary_name: str) -> None:
        self.paths = tuple(sorted({Path(path).resolve() for path in paths if Path(path).is_file()}))
        self.binary_name = binary_name
        self._texts: dict[Path, str] = {}
        self._function_definitions: dict[Path, dict[str, tuple[str, ...]]] = {}
        self._primary_markers: dict[Path, str | None] = {}
        self._dwarf_sources: dict[Path, dict[tuple[str, int], tuple[str, ...]]] = {}
        self._dwarf_errors: dict[Path, str] = {}
        self._binary_contexts: dict[Path, SourceBinaryEvidenceContext] = {}
        self._source_line_indexes: dict[Path, dict[tuple[str, int], str]] = {}

    def _text(self, path: Path) -> str:
        text = self._texts.get(path)
        if text is None:
            text = path.read_text(errors="replace")
            self._texts[path] = text
        return text

    def _function(self, path: Path, function_name: str) -> str | None:
        if is_cxx_preprocessed(path):
            return None
        definitions = self._function_definitions.get(path)
        if definitions is None:
            definitions = index_c_functions(self._text(path))
            self._function_definitions[path] = definitions
        exact = definitions.get(function_name, ())
        return exact[0] if len(exact) == 1 else None

    def _primary_marker(self, path: Path) -> str | None:
        if path in self._primary_markers:
            return self._primary_markers[path]
        marker = re.compile(r'^\s*#\s+\d+\s+"([^"]+)"')
        primary = None
        for line in self._text(path).splitlines():
            match = marker.match(line)
            if not match:
                continue
            candidate = match.group(1)
            if candidate.startswith("<") and candidate.endswith(">"):
                continue
            if candidate.endswith("/") or candidate.endswith("//"):
                continue
            primary = candidate
            break
        self._primary_markers[path] = primary
        return primary

    def _dwarf_source_index(self, binary_path: Path) -> dict[tuple[str, int], tuple[str, ...]]:
        key = binary_path.resolve()
        cached = self._dwarf_sources.get(key)
        if cached is not None:
            return cached

        rows: defaultdict[tuple[str, int], set[str]] = defaultdict(set)
        dwarfinfo = self.binary_context(key).dwarfinfo
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)
            if line_program is None:
                continue
            cu_path = _cu_source_path(cu, line_program)
            if not cu_path:
                continue
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                function_name = die_str_attr(die, "DW_AT_name")
                if not function_name:
                    continue
                for begin, _end in _die_ranges(die, dwarfinfo):
                    rows[(function_name, begin)].add(cu_path)
        index = {identity: tuple(sorted(paths)) for identity, paths in rows.items()}
        self._dwarf_sources[key] = index
        return index

    def binary_context(self, binary_path: Path) -> SourceBinaryEvidenceContext:
        key = binary_path.resolve()
        context = self._binary_contexts.get(key)
        if context is None:
            context = open_source_binary_context(key)
            self._binary_contexts[key] = context
        return context

    def source_line_index(self, source_path: Path) -> dict[tuple[str, int], str]:
        key = source_path.resolve()
        lines = self._source_line_indexes.get(key)
        if lines is None:
            lines = load_source_lines(key, key)
            self._source_line_indexes[key] = lines
        return lines

    def _path_for_cu(self, cu_path: str, function_name: str) -> Path | None:
        candidates = [
            path
            for path in self.paths
            if (primary := self._primary_marker(path)) is not None
            and _path_has_suffix(primary, cu_path)
        ]
        if len(candidates) > 1:
            binary_stem = self.binary_name
            cu_stem = PurePosixPath(cu_path).stem
            preferred = [
                path
                for path in candidates
                if path.stem in {f"{binary_stem}-{cu_stem}", f"{binary_stem}_{cu_stem}"}
                or path.stem.startswith(binary_stem + "-")
                and path.stem.endswith("-" + cu_stem)
            ]
            if len(preferred) == 1:
                candidates = preferred
        if len(candidates) > 1:
            exact = [path for path in candidates if self._function(path, function_name) is not None]
            if len(exact) == 1:
                candidates = exact
        if len(candidates) > 1:
            cu_stem = PurePosixPath(cu_path).stem
            stem_exact = [path for path in candidates if strip_source_ext(path.stem) == cu_stem]
            if len(stem_exact) == 1:
                candidates = stem_exact
        return candidates[0] if len(candidates) == 1 else None

    def _address_pinned_path(
        self,
        binary_path: Path,
        function_name: str,
        function_address: int,
    ) -> Path | None:
        cu_paths = self._dwarf_source_index(binary_path).get(
            (function_name, function_address),
            (),
        )
        selected = {
            path
            for cu_path in cu_paths
            if (path := self._path_for_cu(cu_path, function_name)) is not None
        }
        return next(iter(selected)) if len(selected) == 1 else None

    def select(
        self,
        function_name: str,
        *,
        binary_path: Path | None = None,
        function_address: int | None = None,
    ) -> _SourceSelection:
        """Return an address-pinned TU or one unambiguous exact C definition."""

        errors: list[str] = []
        selected_path = None
        if binary_path is not None and function_address is not None and binary_path.is_file():
            binary_key = binary_path.resolve()
            cached_error = self._dwarf_errors.get(binary_key)
            if cached_error is not None:
                errors.append(cached_error)
            else:
                try:
                    selected_path = self._address_pinned_path(
                        binary_path,
                        function_name,
                        function_address,
                    )
                except Exception as exc:  # noqa: BLE001 - exact C selection remains available
                    cached_error = f"source_pin:{type(exc).__name__}"
                    self._dwarf_errors[binary_key] = cached_error
                    errors.append(cached_error)
        if selected_path is not None:
            try:
                code = self._function(selected_path, function_name)
            except Exception as exc:  # noqa: BLE001 - native address evidence remains available
                errors.append(f"source_index:{type(exc).__name__}")
                code = None
            return _SourceSelection(selected_path, code, tuple(errors))

        candidates: list[tuple[Path, str]] = []
        for path in self.paths:
            if is_cxx_preprocessed(path):
                continue
            try:
                code = self._function(path, function_name)
            except Exception as exc:  # noqa: BLE001 - another exact TU may remain usable
                errors.append(f"source_index:{type(exc).__name__}")
                continue
            if code is None:
                continue
            candidates.append((path, code))
        if len(candidates) != 1:
            return _SourceSelection(None, None, tuple(sorted(set(errors))))
        return _SourceSelection(candidates[0][0], candidates[0][1], tuple(sorted(set(errors))))


def build_source_evidence(
    binary_path: Path | None,
    function_name: str,
    function_address: int,
    ground_truth_vars: list[dict[str, Any]],
    context: PreprocessedSourceContext | None,
) -> SourceEvidenceResult:
    """Join DWARF variables to source addresses and type-blind C usage features."""

    errors: list[str] = []
    selection = _SourceSelection(None, None)
    if context is not None:
        try:
            selection = context.select(
                function_name,
                binary_path=binary_path,
                function_address=function_address,
            )
            errors.extend(selection.errors)
        except Exception as exc:  # noqa: BLE001 - all source evidence is optional
            errors.append(f"source_select:{type(exc).__name__}")
    source_path = selection.path
    source_code = selection.function_code
    native: FunctionEvidence | None = None
    if binary_path is not None and source_path is not None:
        try:
            native = extract_source_evidence(
                binary_path,
                source_path,
                function_name,
                preprocessed_path=source_path,
                include_inlined=True,
                function_address=function_address,
                feature_code=("" if is_cxx_preprocessed(source_path) else source_code),
                source_lines=(
                    context.source_line_index(source_path) if context is not None else None
                ),
                binary_context=(
                    context.binary_context(binary_path) if context is not None else None
                ),
            )
        except Exception as exc:  # noqa: BLE001 - anchors remain a safe fallback
            errors.append(f"native:{type(exc).__name__}")

    native_by_id = (
        {variable.identity: variable for variable in native.variables} if native is not None else {}
    )
    usage = None
    if source_code is not None and source_path is not None and not is_cxx_preprocessed(source_path):
        try:
            usage = analyze_c_function(
                source_code,
                function_name,
                (str(variable.get("name", "")) for variable in ground_truth_vars),
            )
        except Exception as exc:  # noqa: BLE001 - anchors remain a safe fallback
            errors.append(f"usage:{type(exc).__name__}")

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
        features: tuple[tuple[str, int], ...]
        if source_path is not None and is_cxx_preprocessed(source_path):
            features = ()
        elif usage is not None and name:
            features = usage.features.get(name, supplied_features)
        else:
            features = supplied_features
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
        ";".join(sorted(set(errors))) or None,
    )
