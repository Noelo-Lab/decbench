"""Address-evidence matching for experimental local-variable edit distance."""

from __future__ import annotations

import bisect
import contextlib
import re
import struct
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx


@dataclass(frozen=True)
class VariableEvidence:
    identity: str
    name: str
    addresses: frozenset[int] = frozenset()
    stack_offsets: tuple[int, ...] = ()
    size: int | None = None
    kind: str = "local"
    arg_index: int | None = None
    decl_file: str | None = None
    decl_line: int | None = None
    lines: tuple[int, ...] = ()
    live_ranges: tuple[tuple[int, int], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["addresses"] = [f"0x{x:x}" for x in sorted(self.addresses)]
        data["stack_offsets"] = list(self.stack_offsets)
        data["lines"] = list(self.lines)
        data["live_ranges"] = [[f"0x{start:x}", f"0x{end:x}"] for start, end in self.live_ranges]
        return data


@dataclass(frozen=True)
class VariableMatch:
    source_id: str
    decompiled_id: str
    stage: str
    score: float
    intersection: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["intersection"] = [f"0x{x:x}" for x in self.intersection]
        return data


@dataclass
class DistanceResult:
    source_count: int
    decompiled_count: int
    matches: list[VariableMatch]
    unmatched_source: list[str]
    unmatched_decompiled: list[str]
    unobservable_source: list[str]
    stack_shift: int | None
    candidates: dict[str, list[tuple[str, float]]] = field(default_factory=dict)

    @property
    def distance(self) -> int:
        return self.source_count + self.decompiled_count - 2 * len(self.matches)

    @property
    def accuracy(self) -> float:
        denom = self.source_count + self.decompiled_count
        return 1.0 if denom == 0 else 2 * len(self.matches) / denom

    @property
    def strict_distance(self) -> int:
        return self.distance + len(self.unobservable_source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_count": self.source_count,
            "decompiled_count": self.decompiled_count,
            "matched_count": len(self.matches),
            "distance": self.distance,
            "accuracy": self.accuracy,
            "strict_distance": self.strict_distance,
            "stack_shift": self.stack_shift,
            "matches": [match.to_dict() for match in self.matches],
            "unmatched_source": self.unmatched_source,
            "unmatched_decompiled": self.unmatched_decompiled,
            "unobservable_source": self.unobservable_source,
            "candidates": {
                key: [{"decompiled_id": target, "score": score} for target, score in rows]
                for key, rows in self.candidates.items()
            },
        }


@dataclass
class FunctionEvidence:
    name: str
    start: int
    end: int
    variables: list[VariableEvidence]
    code: str = ""
    line_addresses: dict[int, frozenset[int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "variables": [var.to_dict() for var in self.variables],
            "code": self.code,
            "line_addresses": {
                str(line): [f"0x{x:x}" for x in sorted(addresses)]
                for line, addresses in sorted(self.line_addresses.items())
            },
        }


def _size_compatible(source: VariableEvidence, decompiled: VariableEvidence) -> bool:
    return source.size is None or decompiled.size is None or source.size == decompiled.size


def _stack_shift(
    source: list[VariableEvidence],
    decompiled: list[VariableEvidence],
) -> int | None:
    shifts = {
        source_offset - decompiled_offset
        for source_var in source
        for decompiled_var in decompiled
        if _size_compatible(source_var, decompiled_var)
        for source_offset in source_var.stack_offsets
        for decompiled_offset in decompiled_var.stack_offsets
    }
    if not shifts:
        return None

    ranked: list[tuple[int, int, int]] = []
    for shift in shifts:
        graph = nx.Graph()
        for source_var in source:
            graph.add_node(("s", source_var.identity), bipartite=0)
        for decompiled_var in decompiled:
            graph.add_node(("d", decompiled_var.identity), bipartite=1)
        for source_var in source:
            for decompiled_var in decompiled:
                if not _size_compatible(source_var, decompiled_var):
                    continue
                if any(
                    decompiled_offset + shift == source_offset
                    for source_offset in source_var.stack_offsets
                    for decompiled_offset in decompiled_var.stack_offsets
                ):
                    graph.add_edge(
                        ("s", source_var.identity),
                        ("d", decompiled_var.identity),
                    )
        cardinality = len(nx.algorithms.matching.max_weight_matching(graph, maxcardinality=True))
        ranked.append((cardinality, -abs(shift), shift))
    best_cardinality = max(row[0] for row in ranked)
    best = [row for row in ranked if row[0] == best_cardinality]
    if best_cardinality < 2 or len(best) != 1:
        return None
    return best[0][2]


def _weighted_dice(
    source: VariableEvidence,
    decompiled: VariableEvidence,
    weights: dict[int, float],
) -> tuple[float, tuple[int, ...]]:
    intersection = source.addresses & decompiled.addresses
    if not intersection:
        return 0.0, ()
    numerator = 2 * sum(weights[address] for address in intersection)
    denominator = sum(weights[address] for address in source.addresses) + sum(
        weights[address] for address in decompiled.addresses
    )
    if denominator == 0:
        return 0.0, ()
    return numerator / denominator, tuple(sorted(intersection))


def _address_weights(
    source: Iterable[VariableEvidence],
    decompiled: Iterable[VariableEvidence],
) -> dict[int, float]:
    source_degree: dict[int, int] = defaultdict(int)
    decompiled_degree: dict[int, int] = defaultdict(int)
    for var in source:
        for address in var.addresses:
            source_degree[address] += 1
    for var in decompiled:
        for address in var.addresses:
            decompiled_degree[address] += 1
    return {
        address: 1 / max(source_degree[address], decompiled_degree[address])
        for address in source_degree.keys() | decompiled_degree.keys()
    }


def match_variables(
    source: Iterable[VariableEvidence],
    decompiled: Iterable[VariableEvidence],
    *,
    min_overlap: float = 0.1,
    ambiguity_margin: float = 0.03,
) -> DistanceResult:
    source_all = sorted(source, key=lambda var: var.identity)
    decompiled_all = sorted(decompiled, key=lambda var: var.identity)
    observable = [
        var for var in source_all if var.addresses or var.stack_offsets or var.arg_index is not None
    ]
    unobservable = [var for var in source_all if var not in observable]
    source_by_id = {var.identity: var for var in observable}
    decompiled_by_id = {var.identity: var for var in decompiled_all}
    remaining_source = set(source_by_id)
    remaining_decompiled = set(decompiled_by_id)
    matches: list[VariableMatch] = []

    def accept(source_id: str, decompiled_id: str, stage: str, score: float) -> None:
        intersection = tuple(
            sorted(source_by_id[source_id].addresses & decompiled_by_id[decompiled_id].addresses)
        )
        matches.append(VariableMatch(source_id, decompiled_id, stage, score, intersection))
        remaining_source.remove(source_id)
        remaining_decompiled.remove(decompiled_id)

    source_args: dict[int, list[VariableEvidence]] = defaultdict(list)
    decompiled_args: dict[int, list[VariableEvidence]] = defaultdict(list)
    for var in observable:
        if var.arg_index is not None:
            source_args[var.arg_index].append(var)
    for var in decompiled_all:
        if var.arg_index is not None:
            decompiled_args[var.arg_index].append(var)
    for index in sorted(source_args.keys() & decompiled_args.keys()):
        if len(source_args[index]) == len(decompiled_args[index]) == 1:
            accept(
                source_args[index][0].identity,
                decompiled_args[index][0].identity,
                "argument",
                1.0,
            )

    source_stack = [
        source_by_id[key] for key in remaining_source if source_by_id[key].stack_offsets
    ]
    decompiled_stack = [
        decompiled_by_id[key] for key in remaining_decompiled if decompiled_by_id[key].stack_offsets
    ]
    shift = _stack_shift(source_stack, decompiled_stack)
    if shift is not None:
        source_neighbors: dict[str, set[str]] = defaultdict(set)
        decompiled_neighbors: dict[str, set[str]] = defaultdict(set)
        for source_var in source_stack:
            for decompiled_var in decompiled_stack:
                if not _size_compatible(source_var, decompiled_var):
                    continue
                if any(
                    decompiled_offset + shift == source_offset
                    for source_offset in source_var.stack_offsets
                    for decompiled_offset in decompiled_var.stack_offsets
                ):
                    source_neighbors[source_var.identity].add(decompiled_var.identity)
                    decompiled_neighbors[decompiled_var.identity].add(source_var.identity)
        exact_pairs = sorted(
            (source_id, next(iter(targets)))
            for source_id, targets in source_neighbors.items()
            if len(targets) == 1 and len(decompiled_neighbors[next(iter(targets))]) == 1
        )
        for source_id, decompiled_id in exact_pairs:
            if source_id in remaining_source and decompiled_id in remaining_decompiled:
                source_var = source_by_id[source_id]
                decompiled_var = decompiled_by_id[decompiled_id]
                if (
                    source_var.addresses
                    and decompiled_var.addresses
                    and not source_var.addresses & decompiled_var.addresses
                ):
                    continue
                accept(source_id, decompiled_id, "stack", 1.0)

    remaining_source_vars = [source_by_id[key] for key in sorted(remaining_source)]
    remaining_decompiled_vars = [decompiled_by_id[key] for key in sorted(remaining_decompiled)]
    weights = _address_weights(remaining_source_vars, remaining_decompiled_vars)
    edges: dict[tuple[str, str], tuple[float, tuple[int, ...]]] = {}
    for source_var in remaining_source_vars:
        for decompiled_var in remaining_decompiled_vars:
            score, intersection = _weighted_dice(source_var, decompiled_var, weights)
            if score >= min_overlap:
                edges[(source_var.identity, decompiled_var.identity)] = (
                    score,
                    intersection,
                )

    candidates: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for (source_id, decompiled_id), (score, _intersection) in edges.items():
        candidates[source_id].append((decompiled_id, score))
    for rows in candidates.values():
        rows.sort(key=lambda row: (-row[1], row[0]))

    while True:
        active = {
            pair: value
            for pair, value in edges.items()
            if pair[0] in remaining_source and pair[1] in remaining_decompiled
        }
        if not active:
            break
        source_rank: dict[str, list[tuple[str, float]]] = defaultdict(list)
        decompiled_rank: dict[str, list[tuple[str, float]]] = defaultdict(list)
        for (source_id, decompiled_id), (score, _intersection) in active.items():
            source_rank[source_id].append((decompiled_id, score))
            decompiled_rank[decompiled_id].append((source_id, score))
        for rows in source_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))
        for rows in decompiled_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))

        accepted = False
        for (source_id, decompiled_id), (score, _intersection) in sorted(
            active.items(),
            key=lambda row: (-row[1][0], row[0][0], row[0][1]),
        ):
            source_rows = source_rank[source_id]
            decompiled_rows = decompiled_rank[decompiled_id]
            if source_rows[0][0] != decompiled_id or decompiled_rows[0][0] != source_id:
                continue
            source_gap = score - source_rows[1][1] if len(source_rows) > 1 else float("inf")
            decompiled_gap = (
                score - decompiled_rows[1][1] if len(decompiled_rows) > 1 else float("inf")
            )
            if source_gap < ambiguity_margin or decompiled_gap < ambiguity_margin:
                continue
            accept(source_id, decompiled_id, "overlap", score)
            accepted = True
            break
        if not accepted:
            break

    matches.sort(key=lambda match: (match.stage, match.source_id, match.decompiled_id))
    return DistanceResult(
        source_count=len(observable),
        decompiled_count=len(decompiled_all),
        matches=matches,
        unmatched_source=sorted(remaining_source),
        unmatched_decompiled=sorted(remaining_decompiled),
        unobservable_source=sorted(var.identity for var in unobservable),
        stack_shift=shift,
        candidates=dict(candidates),
    )


def mask_elf_metadata(binary_path: Path, output_path: Path) -> None:
    data = bytearray(binary_path.read_bytes())
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{binary_path} is not an ELF binary")
    elf_class, encoding = data[4], data[5]
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
        shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
        offset_field, size_field = 0x18, 0x20
    elif elf_class == 1:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
        shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
        offset_field, size_field = 0x10, 0x14
    else:
        raise ValueError(f"unsupported ELF class {elf_class}")

    shstr_header = shoff + shstrndx * shentsize
    word = "Q" if elf_class == 2 else "I"
    strings_offset = struct.unpack_from(endian + word, data, shstr_header + offset_field)[0]
    strings_size = struct.unpack_from(endian + word, data, shstr_header + size_field)[0]
    strings = data[strings_offset : strings_offset + strings_size]

    for index in range(shnum):
        header = shoff + index * shentsize
        name_offset = struct.unpack_from(endian + "I", data, header)[0]
        if name_offset >= len(strings):
            continue
        end = strings.find(b"\0", name_offset)
        name = bytes(strings[name_offset : end if end >= 0 else None]).decode("ascii", "replace")
        if name.startswith(".debug") or name in {
            ".symtab",
            ".strtab",
            ".gdb_index",
            ".gnu_debuglink",
        }:
            struct.pack_into(endian + "II", data, header, 0, 0)
    output_path.write_bytes(data)
    output_path.chmod(binary_path.stat().st_mode)


def _die_name(die: Any) -> str:
    attr = die.attributes.get("DW_AT_name")
    if attr is None:
        return ""
    value = attr.value
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _die_ranges(
    die: Any,
    dwarfinfo: Any,
    fallback: tuple[tuple[int, int], ...] = (),
) -> tuple[tuple[int, int], ...]:
    from elftools.dwarf.descriptions import describe_form_class
    from elftools.dwarf.ranges import BaseAddressEntry

    low_attr = die.attributes.get("DW_AT_low_pc")
    high_attr = die.attributes.get("DW_AT_high_pc")
    if low_attr is not None and high_attr is not None:
        low = int(low_attr.value)
        high = int(high_attr.value)
        if describe_form_class(high_attr.form) != "address":
            high += low
        return ((low, high),)
    ranges_attr = die.attributes.get("DW_AT_ranges")
    if ranges_attr is None:
        return fallback
    try:
        entries = dwarfinfo.range_lists().get_range_list_at_offset(ranges_attr.value, die.cu)
    except Exception:
        return fallback
    cu_low = die.cu.get_top_DIE().attributes.get("DW_AT_low_pc")
    base = int(cu_low.value) if cu_low is not None else 0
    ranges: list[tuple[int, int]] = []
    for entry in entries:
        if isinstance(entry, BaseAddressEntry):
            base = int(entry.base_address)
        elif entry.is_absolute:
            ranges.append((int(entry.begin_offset), int(entry.end_offset)))
        else:
            ranges.append((base + int(entry.begin_offset), base + int(entry.end_offset)))
    return tuple(ranges) or fallback


def _location_info(
    die: Any,
    dwarfinfo: Any,
    scope_ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, ...], tuple[tuple[int, int], ...]]:
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    from elftools.dwarf.locationlists import BaseAddressEntry, LocationExpr, LocationParser

    attr = die.attributes.get("DW_AT_location")
    if attr is None:
        return (), ()
    parser = LocationParser(dwarfinfo.location_lists())
    expr_parser = DWARFExprParser(dwarfinfo.structs)
    try:
        location = parser.parse_from_attribute(attr, die.cu["version"], die)
    except Exception:
        return (), ()

    offsets: set[int] = set()
    live_ranges: list[tuple[int, int]] = []

    def add_expression(expression: Any) -> None:
        with contextlib.suppress(Exception):
            for operation in expr_parser.parse_expr(expression):
                if operation.op_name == "DW_OP_fbreg":
                    offsets.add(int(operation.args[0]))

    if isinstance(location, LocationExpr):
        add_expression(location.loc_expr)
        return tuple(sorted(offsets)), scope_ranges

    base = scope_ranges[0][0] if scope_ranges else 0
    for entry in location:
        if isinstance(entry, BaseAddressEntry):
            base = int(entry.base_address)
            continue
        expression = getattr(entry, "loc_expr", None)
        if expression is None:
            continue
        add_expression(expression)
        if entry.is_absolute:
            live_ranges.append((int(entry.begin_offset), int(entry.end_offset)))
        else:
            live_ranges.append((base + int(entry.begin_offset), base + int(entry.end_offset)))
    return tuple(sorted(offsets)), tuple(live_ranges)


def _decl_location(die: Any, line_program: Any) -> tuple[str | None, int | None]:
    file_attr = die.attributes.get("DW_AT_decl_file")
    line_attr = die.attributes.get("DW_AT_decl_line")
    if file_attr is None:
        return None, int(line_attr.value) if line_attr is not None else None
    entries = line_program.header["file_entry"]
    index = int(file_attr.value)
    actual = index if die.cu["version"] >= 5 else index - 1
    if not 0 <= actual < len(entries):
        return None, int(line_attr.value) if line_attr is not None else None
    raw_name = entries[actual].name
    name = raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)
    return name, int(line_attr.value) if line_attr is not None else None


def _source_lines(source_path: Path, preprocessed_path: Path | None) -> dict[tuple[str, int], str]:
    lines = {
        (source_path.name, number): text
        for number, text in enumerate(source_path.read_text(errors="replace").splitlines(), start=1)
    }
    if preprocessed_path is None:
        return lines
    marker = re.compile(r'^\s*#\s+(\d+)\s+"([^"]+)"')
    current_file: str | None = None
    current_line = 0
    for text in preprocessed_path.read_text(errors="replace").splitlines():
        match = marker.match(text)
        if match:
            current_line = int(match.group(1))
            current_file = Path(match.group(2)).name
            continue
        if current_file is not None:
            lines.setdefault((current_file, current_line), text)
            current_line += 1
    return lines


def instruction_addresses(
    elf: Any,
    start: int,
    end: int,
) -> list[int]:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    machine = elf["e_machine"]
    if machine != "EM_X86_64" and machine != "EM_386":
        raise ValueError(f"unsupported demo architecture {machine}")
    text = elf.get_section_by_name(".text")
    if text is None:
        return []
    offset = start - int(text["sh_addr"])
    code = text.data()[offset : offset + (end - start)]
    mode = CS_MODE_64 if machine == "EM_X86_64" else CS_MODE_32
    return [instruction.address for instruction in Cs(CS_ARCH_X86, mode).disasm(code, start)]


def extract_source_evidence(
    binary_path: Path,
    source_path: Path,
    function_name: str,
    *,
    preprocessed_path: Path | None = None,
    include_inlined: bool = False,
    function_address: int | None = None,
) -> FunctionEvidence:
    from elftools.elf.elffile import ELFFile

    source_text = _source_lines(source_path, preprocessed_path)
    with binary_path.open("rb") as stream:
        elf = ELFFile(stream)
        dwarfinfo = elf.get_dwarf_info()
        found = None
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != function_name:
                    continue
                if function_address is not None:
                    ranges = _die_ranges(die, dwarfinfo)
                    if not any(begin == function_address for begin, _end in ranges):
                        continue
                found = (cu, die)
                break
            if found is not None:
                break
        if found is None:
            raise ValueError(f"DWARF function {function_name!r} not found")
        cu, function_die = found
        line_program = dwarfinfo.line_program_for_CU(cu)
        function_ranges = _die_ranges(function_die, dwarfinfo)
        if not function_ranges:
            raise ValueError(f"DWARF function {function_name!r} has no address range")
        start = min(begin for begin, _end in function_ranges)
        end = max(finish for _begin, finish in function_ranges)
        instructions = instruction_addresses(elf, start, end)
        inline_ranges: list[tuple[int, int]] = []

        def collect_inline_ranges(parent: Any) -> None:
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine":
                    inline_ranges.extend(_die_ranges(child, dwarfinfo))
                if child.tag in {"DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"}:
                    collect_inline_ranges(child)

        collect_inline_ranges(function_die)

        rows: dict[int, tuple[str, int] | None] = {}
        entries = line_program.header["file_entry"]
        for entry in line_program.get_entries():
            state = entry.state
            if state is None or state.end_sequence or not start <= int(state.address) < end:
                continue
            actual = int(state.file) if cu["version"] >= 5 else int(state.file) - 1
            location: tuple[str, int] | None = None
            if 0 <= actual < len(entries) and state.line is not None:
                raw_name = entries[actual].name
                filename = (
                    raw_name.decode("utf-8", "replace")
                    if isinstance(raw_name, bytes)
                    else str(raw_name)
                )
                location = (Path(filename).name, int(state.line))
            rows[int(state.address)] = location
        row_starts = sorted(rows)
        row_locations = [rows[address] for address in row_starts]

        address_location: dict[int, tuple[str, int]] = {}
        for address in instructions:
            if any(begin <= address < finish for begin, finish in inline_ranges):
                continue
            index = bisect.bisect_right(row_starts, address) - 1
            if index >= 0 and row_locations[index] is not None:
                address_location[address] = row_locations[index]  # type: ignore[assignment]

        raw_variables: list[VariableEvidence] = []
        arg_index = 0

        def walk_scope(
            parent: Any,
            scope_ranges: tuple[tuple[int, int], ...],
        ) -> None:
            nonlocal arg_index
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine" and not include_inlined:
                    continue
                if child.tag in {"DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"}:
                    walk_scope(child, _die_ranges(child, dwarfinfo, scope_ranges))
                    continue
                if child.tag not in {"DW_TAG_formal_parameter", "DW_TAG_variable"}:
                    continue
                name = _die_name(child)
                is_arg = child.tag == "DW_TAG_formal_parameter" and parent is function_die
                this_arg_index = arg_index if is_arg else None
                if is_arg:
                    arg_index += 1
                offsets, live_ranges = _location_info(child, dwarfinfo, scope_ranges)
                decl_file, decl_line = _decl_location(child, line_program)
                size = None
                with contextlib.suppress(Exception):
                    from decbench.metrics.type_match import _parse_type_die

                    _types, size = _parse_type_die(child, dwarfinfo)
                token = re.compile(r"\b" + re.escape(name) + r"\b") if name else None
                addresses: set[int] = set()
                lines: set[int] = set()
                for address, location in address_location.items():
                    if scope_ranges and not any(
                        begin <= address < finish for begin, finish in scope_ranges
                    ):
                        continue
                    text = source_text.get(location)
                    if token is not None and text is not None and token.search(text):
                        addresses.add(address)
                        lines.add(location[1])
                raw_variables.append(
                    VariableEvidence(
                        identity=f"dwarf:0x{child.offset:x}",
                        name=name,
                        addresses=frozenset(addresses),
                        stack_offsets=offsets,
                        size=int(size) if size else None,
                        kind="arg" if is_arg else "local",
                        arg_index=this_arg_index,
                        decl_file=decl_file,
                        decl_line=decl_line,
                        lines=tuple(sorted(lines)),
                        live_ranges=live_ranges,
                    )
                )

        walk_scope(function_die, function_ranges)
        line_addresses: dict[int, set[int]] = defaultdict(set)
        for address, (_filename, line) in address_location.items():
            line_addresses[line].add(address)
        return FunctionEvidence(
            function_name,
            start,
            end,
            raw_variables,
            line_addresses={
                line: frozenset(addresses) for line, addresses in line_addresses.items()
            },
        )


def extract_ida_evidence(
    cfunc: Any,
    *,
    elf_base: int,
    image_base: int,
    function_name: str,
) -> FunctionEvidence:
    import ida_funcs
    import ida_hexrays
    import ida_lines

    pseudocode = cfunc.get_pseudocode()
    lines = [ida_lines.tag_remove(line.line) for line in pseudocode]
    line_addresses: dict[int, set[int]] = defaultdict(set)
    line_addresses[1].add((int(cfunc.entry_ea) - image_base) + elf_base)
    for ida_ea, items in cfunc.get_eamap().items():
        address = (int(ida_ea) - image_base) + elf_base
        for item in items:
            with contextlib.suppress(Exception):
                _x, zero_based_line = cfunc.find_item_coords(item)
                line_addresses[int(zero_based_line) + 1].add(address)

    local_variables = list(cfunc.get_lvars())
    variable_lines: dict[int, set[int]] = defaultdict(set)
    for item in cfunc.treeitems:
        if item.op != ida_hexrays.cot_var:
            continue
        with contextlib.suppress(Exception):
            index = int(item.cexpr.v.idx)
            _x, zero_based_line = cfunc.find_item_coords(item)
            variable_lines[index].add(int(zero_based_line) + 1)

    arg_positions = {
        int(local_index): position for position, local_index in enumerate(cfunc.argidx)
    }
    variables: list[VariableEvidence] = []
    stack_delta = int(cfunc.get_stkoff_delta())
    for index, local in enumerate(local_variables):
        name = str(getattr(local, "name", "") or "")
        if not name:
            continue
        is_arg = index in arg_positions
        stack_offsets: tuple[int, ...] = ()
        with contextlib.suppress(Exception):
            if local.location.is_stkoff():
                stack_offsets = (int(local.location.stkoff()) - stack_delta,)
        size = int(local.width) if getattr(local, "width", None) else None
        var_lines = tuple(sorted(variable_lines.get(index, set())))
        addresses = frozenset(
            address for line in var_lines for address in line_addresses.get(line, set())
        )
        variables.append(
            VariableEvidence(
                identity=f"ida:{index}",
                name=name,
                addresses=addresses,
                stack_offsets=stack_offsets,
                size=size,
                kind="arg" if is_arg else "local",
                arg_index=arg_positions.get(index),
                lines=var_lines,
            )
        )

    function = ida_funcs.get_func(cfunc.entry_ea)
    ida_end = int(function.end_ea) if function is not None else int(cfunc.entry_ea)
    start = (int(cfunc.entry_ea) - image_base) + elf_base
    end = (ida_end - image_base) + elf_base
    return FunctionEvidence(
        function_name,
        start,
        end,
        variables,
        code="\n".join(lines),
        line_addresses={line: frozenset(addresses) for line, addresses in line_addresses.items()},
    )


def extract_decompiler_evidence(
    function: Any,
    *,
    backend: str,
    function_name: str | None = None,
    function_end: int | None = None,
) -> FunctionEvidence:
    base_backend = backend.split("@", 1)[0]
    line_addresses = {
        int(mapping.line_number): frozenset(int(address) for address in mapping.addresses)
        for mapping in function.line_mappings
    }
    code_lines = function.decompiled_code.splitlines()
    variables: list[VariableEvidence] = []
    for index, variable in enumerate(function.variables):
        if not variable.name:
            continue
        lines = {int(line) for line in getattr(variable, "line_numbers", [])}
        if not lines and base_backend not in {"ida", "ghidra"}:
            token = re.compile(r"\b" + re.escape(variable.name) + r"\b")
            lines = {
                line_number
                for line_number, text in enumerate(code_lines, start=1)
                if token.search(text)
            }
        addresses = {int(address) for address in getattr(variable, "addresses", [])}
        if not addresses:
            addresses = {
                address for line in lines for address in line_addresses.get(line, frozenset())
            }
        stack_offsets = (int(variable.stack_offset),) if variable.stack_offset is not None else ()
        variables.append(
            VariableEvidence(
                identity=f"{backend}:{index}",
                name=variable.name,
                addresses=frozenset(addresses),
                stack_offsets=stack_offsets,
                size=variable.size,
                kind="arg" if variable.kind == "arg" else "local",
                arg_index=variable.arg_index,
                lines=tuple(sorted(lines)),
            )
        )
    observed_addresses = {address for addresses in line_addresses.values() for address in addresses}
    start = int(function.address)
    end = (
        int(function_end)
        if function_end is not None
        else max(observed_addresses, default=start) + 1
    )
    return FunctionEvidence(
        function_name or function.name,
        start,
        end,
        variables,
        code=function.decompiled_code,
        line_addresses=line_addresses,
    )
