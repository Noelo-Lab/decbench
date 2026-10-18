"""Experimental native-address/source-origin joins for C++ GED.

This index retains definitions instead of reducing them by display name. Failed
or ambiguous evidence never falls back to a same-named function in another TU.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from networkx import DiGraph

from decbench.metrics.variable_features import FunctionDefinition, function_definitions
from decbench.models.decompilation import DecompilationResult
from decbench.utils import binfmt
from decbench.utils.cfg import (
    _is_system_header,
    is_degenerate_source_cfg,
    preprocess_decompiled_c,
    sanitize_decompiled_c,
)
from decbench.utils.compilation_units import (
    CompilationUnitBinding,
    compilation_path,
    saved_temp_units,
)
from decbench.utils.native_code import die_ranges

_MARKER = re.compile(r'^\s*#\s*(?:line\s+)?(\d+)\s+"((?:\\.|[^"\\])*)"(.*)$')


def source_path(path: str) -> str:
    """Normalize separators without interpreting C escapes as Unicode escapes."""
    return compilation_path(path)


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _absolute(path: str, directory: str) -> str:
    return compilation_path(path, directory)


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line: int


@dataclass
class OriginSource:
    """Physical lines remain aligned with the preprocessed input."""

    text: str
    origins: dict[int, SourceLocation]
    primary: str | None
    filtered_paths: frozenset[str] = frozenset()


def origin_source(text: str, *, retain_paths: frozenset[str] = frozenset()) -> OriginSource:
    lines: list[str] = []
    origins: dict[int, SourceLocation] = {}
    current = ""
    logical = 0
    system = True
    primary = None
    filtered: set[str] = set()
    for physical, line in enumerate(text.splitlines(), 1):
        marker = _MARKER.match(line)
        if marker:
            logical = int(marker[1])
            current = source_path(re.sub(r'\\([\\"])', r"\1", marker[2]))
            system = _is_system_header(current) or "3" in marker[3].split()
            if primary is None and not system and logical <= 1 and not current.endswith("/"):
                primary = current
            if system and current and not current.startswith("<") and current in retain_paths:
                system = False
            lines.append("")
            continue
        if not system and current and logical > 0:
            lines.append(line)
            origins[physical] = SourceLocation(current, logical)
        else:
            lines.append("")
            if current and logical > 0:
                filtered.add(current)
        logical += 1
    return OriginSource("\n".join(lines) + "\n", origins, primary, frozenset(filtered))


@dataclass
class CfgDefinition:
    name: str
    fullname: str
    signature: str
    start: int
    end: int
    cfg: DiGraph


class CfgParseError(ValueError):
    """Explicit front-end error diagnostics, distinct from evaluator failures."""


def parse_definitions(text: str, filename: str, language: str) -> list[CfgDefinition]:
    """Use the non-reducing Rust Joern API and exclude declaration-only methods."""
    from rust_joern import parse_code

    parsed = parse_code(text, filename=filename, language=language, strict=False, preprocessed=True)
    errors = [row for row in parsed.diagnostics if row["severity"] == "error"]
    if errors:
        raise CfgParseError(
            "\n".join(
                f"{row['filename']}:{row['line']}:{row['column']}: {row['message']}"
                for row in errors
            )
        )
    definitions = []
    for function in parsed.functions:
        nodes = function.raw["cpg"]["nodes"]
        bodies = [node for node in nodes if node["kind"] == "BLOCK" and node.get("code")]
        if not bodies or function.name == "<global>":
            continue
        definitions.append(
            CfgDefinition(
                function.name,
                function.fullname,
                function.signature,
                function.start_line,
                function.end_line,
                function.cfg,
            )
        )
    return definitions


@dataclass
class CfgJoin:
    cfgs: dict[str, DiGraph] = field(default_factory=dict)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)


def decompiled_cfgs(result: DecompilationResult) -> CfgJoin:
    """A unique definition belongs to its record even when display names differ."""
    joined = CfgJoin()
    for key, function in result.functions.items():
        code = function.decompiled_code
        if not code.strip():
            joined.evidence[key] = {"status": "empty_output"}
            continue
        code = preprocess_decompiled_c(sanitize_decompiled_c(code))
        try:
            definitions = parse_definitions(code, "decompiled.cpp", "c++")
        except CfgParseError as error:
            joined.evidence[key] = {"status": "parser_failure", "error": str(error)}
            continue
        if len(definitions) != 1:
            joined.evidence[key] = {
                "status": "ambiguous_definitions" if definitions else "missing_definition",
                "definitions": [definition.fullname for definition in definitions],
            }
            continue
        definition = definitions[0]
        joined.cfgs[key] = definition.cfg
        joined.evidence[key] = {
            "status": "matched",
            "address": function.address,
            "definition": definition.fullname,
            "span": [definition.start, definition.end],
        }
    return joined


@dataclass(frozen=True)
class NativeSource:
    address: int
    name: str
    units: tuple[str, ...]
    location: SourceLocation | None
    identity: str
    qualified_name: str | None = None
    scope_known: bool = True
    compilation_directory: str | None = None
    physical_unit: str | None = None
    unit_binding: CompilationUnitBinding | None = None


class NativeSourceIndex(dict[int, list[NativeSource]]):
    """Reusable native facts are bound to one immutable binary image."""

    def __init__(self, binary: Path, rows: dict[int, list[NativeSource]]) -> None:
        super().__init__(rows)
        self.binary_path = binary.resolve()
        self.binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.compilation_database: Path | None = None
        self.compilation_database_sha256: str | None = None

    def validate(self, binary: Path) -> None:
        if binary.resolve() != self.binary_path:
            raise ValueError("native source index belongs to another binary")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != self.binary_sha256:
            raise ValueError("native source index binary contents changed")
        if (
            self.compilation_database is not None
            and hashlib.sha256(self.compilation_database.read_bytes()).hexdigest()
            != self.compilation_database_sha256
        ):
            raise ValueError("native source index compilation database changed")

    def with_compilation_database(self, database: Path) -> NativeSourceIndex:
        self.validate(self.binary_path)
        bindings = saved_temp_units(database)
        rows: dict[int, list[NativeSource]] = {}
        for address, records in self.items():
            rows[address] = []
            for record in records:
                binding = bindings.get(record.physical_unit or "")
                if binding is not None and binding.directory == record.compilation_directory:
                    record = replace(
                        record,
                        units=tuple(dict.fromkeys((*record.units, binding.source_file))),
                        unit_binding=binding,
                    )
                rows[address].append(record)
        result = NativeSourceIndex(self.binary_path, rows)
        result.compilation_database = database.resolve()
        result.compilation_database_sha256 = hashlib.sha256(database.read_bytes()).hexdigest()
        return result


def _dwarf_files(dwarf: Any, cu: Any) -> dict[int, str]:
    top = cu.get_top_DIE()
    directory_attr = top.attributes.get("DW_AT_comp_dir")
    directory = _text(directory_attr.value) if directory_attr else ""
    program = dwarf.line_program_for_CU(cu)
    if program is None:
        return {}
    version = int(program.header.version)
    dirs = [_text(value) for value in program["include_directory"]]
    files = {}
    for index, entry in enumerate(program["file_entry"], 0 if version >= 5 else 1):
        folder_index = int(entry.dir_index)
        folder = (
            dirs[folder_index]
            if version >= 5 and folder_index < len(dirs)
            else dirs[folder_index - 1] if 0 < folder_index <= len(dirs) else directory
        )
        files[index] = _absolute(_text(entry.name), _absolute(folder, directory))
    return files


def _dwarf_qualified_name(die: Any) -> str | None:
    attr, owner = binfmt.die_attr_owner(die, "DW_AT_name")
    if attr is None or owner is None:
        return None
    names = [_text(attr.value)]
    parent = owner.get_parent()
    while parent is not None:
        if parent.tag in {
            "DW_TAG_namespace",
            "DW_TAG_class_type",
            "DW_TAG_structure_type",
            "DW_TAG_union_type",
        }:
            name = parent.attributes.get("DW_AT_name")
            if name is None:
                return None
            names.append(_text(name.value))
        elif parent.tag in {"DW_TAG_subprogram", "DW_TAG_lexical_block"}:
            return None
        parent = parent.get_parent()
    return "::".join(reversed(names))


def native_sources(binary: Path, addresses: set[int]) -> NativeSourceIndex:
    """Retain concrete records and reject ambiguity at resolution, including ICF."""
    rows: dict[int, list[NativeSource]] = defaultdict(list)
    dwarf = binfmt.dwarf_info(binary)
    if dwarf is None:
        pdb = binfmt.pdb_info(binary)
        if pdb is not None:
            for function in pdb.functions:
                if function.address in addresses:
                    rows[function.address].append(
                        NativeSource(
                            function.address,
                            function.name,
                            tuple(source_path(path) for path in function.source_files),
                            (
                                SourceLocation(
                                    source_path(function.source_file), function.source_line
                                )
                                if function.source_file and function.source_line > 0
                                else None
                            ),
                            f"pdb:{function.module}:{function.address:x}:{function.name}",
                        )
                    )
        return NativeSourceIndex(binary, dict(rows))
    for cu in dwarf.iter_CUs():
        top = cu.get_top_DIE()
        unit_attr = top.attributes.get("DW_AT_name")
        directory_attr = top.attributes.get("DW_AT_comp_dir")
        unit = _absolute(
            _text(unit_attr.value) if unit_attr else "",
            _text(directory_attr.value) if directory_attr else "",
        )
        file_tables: dict[int, dict[int, str]] = {}
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            ranges = die_ranges(die, dwarf)
            low = die.attributes.get("DW_AT_entry_pc") or die.attributes.get("DW_AT_low_pc")
            address = int(low.value) if low else ranges[0][0] if ranges else None
            if address not in addresses or not ranges:
                continue
            if not binfmt.dwarf_low_pc_is_concrete(binary, address):
                continue
            name = binfmt.die_str_attr(die, "DW_AT_name")
            if not name:
                continue
            file_attr, owner = binfmt.die_attr_owner(die, "DW_AT_decl_file")
            line_attr = binfmt.die_attr(die, "DW_AT_decl_line")
            location = None
            if file_attr is not None and owner is not None and line_attr is not None:
                if owner.cu.cu_offset not in file_tables:
                    file_tables[owner.cu.cu_offset] = _dwarf_files(dwarf, owner.cu)
                path = file_tables[owner.cu.cu_offset].get(int(file_attr.value))
                if path and int(line_attr.value) > 0:
                    location = SourceLocation(path, int(line_attr.value))
            qualified_name = _dwarf_qualified_name(die)
            rows[address].append(
                NativeSource(
                    address,
                    name,
                    (unit,),
                    location,
                    f"dwarf:{die.offset:x}",
                    qualified_name,
                    qualified_name is not None,
                    source_path(_text(directory_attr.value)) if directory_attr else None,
                    unit,
                )
            )
    return NativeSourceIndex(binary, dict(rows))


def source_unit_matches(unit: str | None, record: NativeSource) -> bool:
    if unit is None:
        return False
    return compilation_path(unit, record.compilation_directory) in record.units


def _location_matches(
    location: SourceLocation, locations: frozenset[SourceLocation], record: NativeSource
) -> bool:
    return any(
        candidate.line == location.line
        and compilation_path(candidate.path, record.compilation_directory) == location.path
        for candidate in locations
    )


@dataclass
class SourceCfgIndex:
    definitions: list[tuple[str, str | None, FunctionDefinition, frozenset[SourceLocation]]] = (
        field(default_factory=list)
    )
    inputs: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self, text: str, filename: str, *, native_records: tuple[NativeSource, ...] = ()
    ) -> None:
        """Index a preprocessed C++ TU with full physical/logical origin evidence."""
        source = origin_source(text)
        retained = frozenset(
            path
            for path in source.filtered_paths
            for record in native_records
            if record.location is not None
            and source_unit_matches(source.primary, record)
            and compilation_path(path, record.compilation_directory) == record.location.path
        )
        if retained:
            source = origin_source(text, retain_paths=retained)
        report: dict[str, Any] = {
            "input": filename,
            "unit": source.primary,
            "origin_paths": sorted({location.path for location in source.origins.values()}),
            "filtered_origin_paths": sorted(source.filtered_paths),
            "retained_origin_paths": sorted(retained),
        }
        definitions = function_definitions(source.text)
        for definition in definitions:
            locations = frozenset(
                source.origins[line]
                for line in range(definition.start_line, definition.end_line + 1)
                if line in source.origins
            )
            self.definitions.append((filename, source.primary, definition, locations))
        report.update(status="indexed", definitions=len(definitions))
        self.inputs.append(report)

    def resolve(
        self, result: DecompilationResult, native: dict[int, list[NativeSource]]
    ) -> CfgJoin:
        joined = CfgJoin()
        for key, function in result.functions.items():
            records = native.get(function.address, [])
            if len(records) != 1:
                joined.evidence[key] = {
                    "status": "ambiguous_native_identity" if records else "missing_native_identity",
                    "identities": [record.identity for record in records],
                }
                continue
            record = records[0]
            evidence: dict[str, Any] = {"address": function.address, "native": record.identity}
            if record.location is None:
                evidence["status"] = "missing_native_source_location"
                joined.evidence[key] = evidence
                continue
            evidence.update(
                path=record.location.path,
                line=record.location.line,
                native_name=record.name,
                native_qualified_name=record.qualified_name,
                native_units=list(record.units),
                compilation_directory=record.compilation_directory,
                unit_binding=asdict(record.unit_binding) if record.unit_binding else None,
            )
            candidates = [
                (filename, definition)
                for filename, unit, definition, locations in self.definitions
                if source_unit_matches(unit, record)
                and _location_matches(record.location, locations, record)
            ]
            if len(candidates) != 1:
                units = [row for row in self.inputs if source_unit_matches(row["unit"], record)]
                missing = (
                    "missing_source_tu"
                    if not units
                    else (
                        (
                            "filtered_source_origin"
                            if any(
                                compilation_path(path, record.compilation_directory)
                                == record.location.path
                                for row in units
                                for path in row["filtered_origin_paths"]
                            )
                            else "missing_source_origin"
                        )
                        if not any(
                            compilation_path(path, record.compilation_directory)
                            == record.location.path
                            for row in units
                            for path in row["origin_paths"]
                        )
                        else "missing_source_definition"
                    )
                )
                evidence.update(
                    status=("ambiguous_source_definition" if candidates else missing),
                    candidates=[(file, definition.name) for file, definition in candidates],
                )
            else:
                filename, definition = candidates[0]
                evidence.update(
                    input=filename,
                    definition=definition.name,
                    definition_sha256=hashlib.sha256(definition.code.encode("utf-8")).hexdigest(),
                    span=[definition.start_line, definition.end_line],
                    parser_scope="definition_only",
                )
                native_name = record.qualified_name or record.name
                if not record.scope_known:
                    evidence["status"] = "missing_native_scope"
                elif definition.is_template:
                    evidence["status"] = "unsupported_template_specialization"
                elif native_name != definition.name:
                    evidence["status"] = "source_name_mismatch"
                elif definition.has_error:
                    evidence["status"] = "source_syntax_error"
                else:
                    try:
                        parsed = parse_definitions(definition.code, filename, "c++")
                    except CfgParseError as error:
                        evidence.update(status="parser_failure", error=str(error))
                    else:
                        if len(parsed) != 1:
                            evidence["status"] = "ambiguous_parser_definition"
                        elif is_degenerate_source_cfg(parsed[0].cfg):
                            evidence["status"] = "degenerate_source_cfg"
                        else:
                            joined.cfgs[key] = parsed[0].cfg
                            evidence.update(status="matched", signature=parsed[0].signature)
            joined.evidence[key] = evidence
        return joined
