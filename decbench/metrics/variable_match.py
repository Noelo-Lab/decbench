"""Address-evidence matching for local-variable correspondence."""

from __future__ import annotations

import bisect
import contextlib
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decbench.utils.native_code import (
    decode_instruction_starts,
    die_ranges,
    entry_address_candidates,
)


@dataclass(frozen=True)
class VariableEvidence:
    identity: str
    addresses: frozenset[int] = frozenset()
    stack_offsets: tuple[int, ...] = ()
    arg_index: int | None = None


@dataclass(frozen=True)
class VariableMatch:
    source_id: str
    decompiled_id: str
    stage: str


@dataclass
class VariableMatchResult:
    matches: list[VariableMatch]
    unmatched_source: list[str]
    unmatched_decompiled: list[str]
    unobservable_source: list[str]
    stack_shift: int | None


@dataclass
class SourceBinaryEvidenceContext:
    stream: Any
    elf: Any
    dwarfinfo: Any
    functions: dict[tuple[str, int], tuple[Any, Any]]
    line_rows: dict[
        int,
        tuple[tuple[int, ...], tuple[tuple[str, int] | None, ...]],
    ] = field(default_factory=dict)
    binary_path: Path | None = None
    binary_info: Any = None
    code_regions: tuple[tuple[int, bytes], ...] = ()
    arm_mclass: bool = False

    def close(self) -> None:
        if self.stream is not None:
            self.stream.close()


def _maximum_bipartite_cardinality(neighbors: Mapping[str, set[str]]) -> int:
    matched_decompiled: dict[str, str] = {}

    def augment(source_id: str, seen: set[str]) -> bool:
        for decompiled_id in sorted(neighbors[source_id]):
            if decompiled_id in seen:
                continue
            seen.add(decompiled_id)
            previous = matched_decompiled.get(decompiled_id)
            if previous is None or augment(previous, seen):
                matched_decompiled[decompiled_id] = source_id
                return True
        return False

    return sum(augment(source_id, set()) for source_id in sorted(neighbors))


def _stack_shift(
    source: list[VariableEvidence],
    decompiled: list[VariableEvidence],
) -> int | None:
    shifts = {
        source_offset - decompiled_offset
        for source_var in source
        for decompiled_var in decompiled
        for source_offset in source_var.stack_offsets
        for decompiled_offset in decompiled_var.stack_offsets
    }
    if not shifts:
        return None

    decompiled_by_offset: defaultdict[int, list[VariableEvidence]] = defaultdict(list)
    for variable in decompiled:
        for offset in set(variable.stack_offsets):
            decompiled_by_offset[offset].append(variable)

    ranked: list[tuple[int, int]] = []
    for shift in shifts:
        neighbors: defaultdict[str, set[str]] = defaultdict(set)
        for source_var in source:
            for source_offset in set(source_var.stack_offsets):
                for decompiled_var in decompiled_by_offset.get(source_offset - shift, ()):
                    neighbors[source_var.identity].add(decompiled_var.identity)

        cardinality = _maximum_bipartite_cardinality(neighbors)
        ranked.append((cardinality, shift))
    best_cardinality = max(row[0] for row in ranked)
    best = [row for row in ranked if row[0] == best_cardinality]
    if best_cardinality < 2 or len(best) != 1:
        return None
    return best[0][1]


def _weighted_dice(
    source: VariableEvidence,
    decompiled: VariableEvidence,
    weights: dict[int, float],
) -> float:
    intersection = source.addresses & decompiled.addresses
    if not intersection:
        return 0.0
    numerator = 2 * sum(weights[address] for address in intersection)
    denominator = sum(weights[address] for address in source.addresses) + sum(
        weights[address] for address in decompiled.addresses
    )
    if denominator == 0:
        return 0.0
    return numerator / denominator


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
    stack_shift_hint: int | None = None,
) -> VariableMatchResult:
    if min_overlap < 0 or ambiguity_margin < 0:
        raise ValueError("matcher thresholds and ambiguity margins must be non-negative")
    source_all = sorted(source, key=lambda var: var.identity)
    decompiled_all = sorted(decompiled, key=lambda var: var.identity)
    observable = [
        var for var in source_all if var.addresses or var.stack_offsets or var.arg_index is not None
    ]
    observable_ids = {var.identity for var in observable}
    unobservable = [var for var in source_all if var.identity not in observable_ids]
    source_by_id = {var.identity: var for var in observable}
    decompiled_by_id = {var.identity: var for var in decompiled_all}
    remaining_source = set(source_by_id)
    remaining_decompiled = set(decompiled_by_id)
    matches: list[VariableMatch] = []

    def accept(
        source_id: str,
        decompiled_id: str,
        stage: str,
    ) -> None:
        matches.append(VariableMatch(source_id, decompiled_id, stage))
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
            )

    source_stack = [
        source_by_id[key] for key in remaining_source if source_by_id[key].stack_offsets
    ]
    decompiled_stack = [
        decompiled_by_id[key] for key in remaining_decompiled if decompiled_by_id[key].stack_offsets
    ]
    shift = _stack_shift(
        source_stack,
        decompiled_stack,
    )
    if shift is None:
        shift = stack_shift_hint
    if shift is not None:
        source_neighbors: dict[str, set[str]] = defaultdict(set)
        decompiled_neighbors: dict[str, set[str]] = defaultdict(set)
        for source_var in source_stack:
            for decompiled_var in decompiled_stack:
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
                accept(source_id, decompiled_id, "stack")

    remaining_source_vars = [source_by_id[key] for key in sorted(remaining_source)]
    remaining_decompiled_vars = [decompiled_by_id[key] for key in sorted(remaining_decompiled)]
    address_weights = _address_weights(remaining_source_vars, remaining_decompiled_vars)
    edges: dict[tuple[str, str], float] = {}
    for source_var in remaining_source_vars:
        for decompiled_var in remaining_decompiled_vars:
            score = _weighted_dice(source_var, decompiled_var, address_weights)
            if score >= min_overlap:
                edges[(source_var.identity, decompiled_var.identity)] = score

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
        for (source_id, decompiled_id), score in active.items():
            source_rank[source_id].append((decompiled_id, score))
            decompiled_rank[decompiled_id].append((source_id, score))
        for rows in source_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))
        for rows in decompiled_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))

        accepted = False
        for (source_id, decompiled_id), score in sorted(
            active.items(),
            key=lambda row: (-row[1], row[0][0], row[0][1]),
        ):
            source_rows = source_rank[source_id]
            decompiled_rows = decompiled_rank[decompiled_id]
            if source_rows[0][0] != decompiled_id or decompiled_rows[0][0] != source_id:
                continue
            source_gap = score - source_rows[1][1] if len(source_rows) > 1 else None
            decompiled_gap = score - decompiled_rows[1][1] if len(decompiled_rows) > 1 else None
            gaps = (source_gap, decompiled_gap)
            if any(gap is not None and gap < ambiguity_margin for gap in gaps):
                continue
            accept(source_id, decompiled_id, "overlap")
            accepted = True
            break
        if not accepted:
            break

    matches.sort(key=lambda match: (match.stage, match.source_id, match.decompiled_id))
    return VariableMatchResult(
        matches=matches,
        unmatched_source=sorted(remaining_source),
        unmatched_decompiled=sorted(remaining_decompiled),
        unobservable_source=sorted(var.identity for var in unobservable),
        stack_shift=shift,
    )


def _die_name(die: Any) -> str:
    from decbench.utils.binfmt import die_str_attr

    return die_str_attr(die, "DW_AT_name") or ""


def open_source_binary_context(binary_path: Path) -> SourceBinaryEvidenceContext:
    from decbench.utils import binfmt

    binary_path = binary_path.resolve()
    binary_info = binfmt.detect(binary_path)
    if binary_info is None:
        raise ValueError(f"unsupported binary format: {binary_path}")

    stream = None
    elf = None
    if binary_info.fmt == "elf":
        from elftools.elf.elffile import ELFFile

        stream = binary_path.open("rb")
        try:
            elf = ELFFile(stream)
            dwarfinfo = elf.get_dwarf_info()
        except Exception:
            stream.close()
            raise
    else:
        dwarfinfo = binfmt.dwarf_info(binary_path)
        if dwarfinfo is None:
            raise ValueError(f"binary has no DWARF information: {binary_path}")

    functions: dict[tuple[str, int], tuple[Any, Any]] = {}
    try:
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name = _die_name(die)
                if not name:
                    continue
                for begin, _end in die_ranges(die, dwarfinfo):
                    functions.setdefault((name, begin), (cu, die))
    except Exception:
        if stream is not None:
            stream.close()
        raise
    return SourceBinaryEvidenceContext(
        stream=stream,
        elf=elf,
        dwarfinfo=dwarfinfo,
        functions=functions,
        binary_path=binary_path,
        binary_info=binary_info,
        code_regions=binfmt.executable_regions(binary_path),
        arm_mclass=(
            binary_info.fmt == "elf"
            and binary_info.arch == "arm"
            and binfmt.elf_is_arm_mclass(binary_path)
        ),
    )


def _location_offsets(
    die: Any,
    dwarfinfo: Any,
) -> tuple[int, ...]:
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    from elftools.dwarf.locationlists import BaseAddressEntry, LocationExpr, LocationParser

    attr = die.attributes.get("DW_AT_location")
    if attr is None:
        return ()
    parser = LocationParser(dwarfinfo.location_lists())
    expr_parser = DWARFExprParser(dwarfinfo.structs)
    try:
        location = parser.parse_from_attribute(attr, die.cu["version"], die)
    except Exception:
        return ()

    offsets: set[int] = set()

    def add_expression(expression: Any) -> None:
        with contextlib.suppress(Exception):
            for operation in expr_parser.parse_expr(expression):
                if operation.op_name == "DW_OP_fbreg":
                    offsets.add(int(operation.args[0]))

    if isinstance(location, LocationExpr):
        add_expression(location.loc_expr)
        return tuple(sorted(offsets))

    for entry in location:
        if isinstance(entry, BaseAddressEntry):
            continue
        expression = getattr(entry, "loc_expr", None)
        if expression is not None:
            add_expression(expression)
    return tuple(sorted(offsets))


def _line_program_rows(
    cu: Any,
    line_program: Any,
) -> tuple[tuple[int, ...], tuple[tuple[str, int] | None, ...]]:
    rows: dict[int, tuple[str, int] | None] = {}
    entries = line_program.header["file_entry"]
    version = int(line_program.header.get("version", cu["version"]))
    for entry in line_program.get_entries():
        state = entry.state
        if state is None or state.end_sequence:
            continue
        actual = int(state.file) if version >= 5 else int(state.file) - 1
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
    starts = tuple(sorted(rows))
    return starts, tuple(rows[address] for address in starts)


def _context_line_program_rows(
    binary_context: SourceBinaryEvidenceContext,
    cu: Any,
    line_program: Any,
) -> tuple[tuple[int, ...], tuple[tuple[str, int] | None, ...]]:
    key = int(cu.cu_offset)
    rows = binary_context.line_rows.get(key)
    if rows is None:
        rows = _line_program_rows(cu, line_program)
        binary_context.line_rows[key] = rows
    return rows


def source_file_lines(source_path: Path) -> dict[tuple[str, int], str]:
    """Read one source file into the ``(basename, line)`` lookup used by DWARF.

    This is intentionally separate from :func:`preprocessed_line_marker_lines`
    so batch scorers can cache a large ``.i`` translation unit once while
    extracting evidence for many functions from it.
    """

    return {
        (source_path.name, number): text
        for number, text in enumerate(source_path.read_text(errors="replace").splitlines(), start=1)
    }


def preprocessed_line_marker_lines(
    preprocessed_path: Path,
) -> dict[tuple[str, int], str]:
    """Parse GCC/Clang line markers from a preprocessed translation unit."""

    lines: dict[tuple[str, int], str] = {}
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


def load_source_lines(
    source_path: Path,
    preprocessed_path: Path | None,
) -> dict[tuple[str, int], str]:
    """Build source-line text keyed the same way as the DWARF line table."""

    lines = source_file_lines(source_path)
    if preprocessed_path is not None:
        for location, text in preprocessed_line_marker_lines(preprocessed_path).items():
            lines.setdefault(location, text)
    return lines


def instruction_addresses(
    elf: Any | None,
    start: int,
    end: int,
    binary_context: SourceBinaryEvidenceContext | None = None,
    function_name: str | None = None,
) -> list[int]:
    from decbench.utils import binfmt

    regions: tuple[tuple[int, bytes], ...]
    if binary_context is None:
        if elf is None:
            return []
        machine = elf["e_machine"]
        info = {
            "EM_X86_64": binfmt.BinInfo("elf", "x86-64", 64),
            "EM_386": binfmt.BinInfo("elf", "x86", 32),
            "EM_ARM": binfmt.BinInfo("elf", "arm", 32),
            "EM_AARCH64": binfmt.BinInfo("elf", "aarch64", 64),
        }.get(machine)
        if info is None:
            raise ValueError(f"unsupported architecture {machine}")
        text = elf.get_section_by_name(".text")
        if text is None:
            return []
        regions = ((int(text["sh_addr"]), bytes(text.data())),)
    else:
        info = binary_context.binary_info
        regions = binary_context.code_regions
        if info is None:
            return []

    decode_start = start
    thumb = False
    if info.arch == "arm":
        thumb = bool(start & 1)
        decode_start &= ~1
        if (
            binary_context is not None
            and binary_context.binary_path is not None
            and info.fmt == "elf"
        ):
            thumb = thumb or binfmt.elf_function_is_thumb(
                binary_context.binary_path,
                function_name or "",
                decode_start,
            )
    return sorted(
        decode_instruction_starts(
            info,
            ((decode_start, end),),
            regions,
            thumb=thumb,
            mclass=thumb and binary_context is not None and binary_context.arm_mclass,
        )
    )


def extract_source_evidence(
    binary_path: Path,
    source_path: Path,
    function_name: str,
    *,
    preprocessed_path: Path | None = None,
    include_inlined: bool = False,
    function_address: int | None = None,
    source_lines: Mapping[tuple[str, int], str] | None = None,
    binary_context: SourceBinaryEvidenceContext | None = None,
) -> list[VariableEvidence]:
    source_text = (
        source_lines
        if source_lines is not None
        else load_source_lines(source_path, preprocessed_path)
    )
    with contextlib.ExitStack() as stack:
        if binary_context is None:
            binary_context = open_source_binary_context(binary_path)
            stack.callback(binary_context.close)
        elf = binary_context.elf
        dwarfinfo = binary_context.dwarfinfo
        entry_addresses = (
            entry_address_candidates(function_address) if function_address is not None else ()
        )
        found = None
        if binary_context is not None and function_address is not None:
            for candidate in entry_addresses:
                found = binary_context.functions.get((function_name, candidate))
                if found is not None:
                    break
        for cu in dwarfinfo.iter_CUs():
            if found is not None:
                break
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != function_name:
                    continue
                if function_address is not None:
                    ranges = die_ranges(die, dwarfinfo)
                    if not any(begin in entry_addresses for begin, _end in ranges):
                        continue
                found = (cu, die)
                break
            if found is not None:
                break
        if found is None:
            raise ValueError(f"DWARF function {function_name!r} not found")
        cu, function_die = found
        line_program = dwarfinfo.line_program_for_CU(cu)
        if line_program is None:
            raise ValueError(f"DWARF function {function_name!r} has no line program")
        function_ranges = die_ranges(function_die, dwarfinfo)
        if not function_ranges:
            raise ValueError(f"DWARF function {function_name!r} has no address range")
        start = min(begin for begin, _end in function_ranges)
        end = max(finish for _begin, finish in function_ranges)
        instructions = instruction_addresses(
            elf,
            start,
            end,
            binary_context,
            function_name=function_name,
        )
        inline_ranges: list[tuple[int, int]] = []

        def collect_inline_ranges(parent: Any) -> None:
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine":
                    inline_ranges.extend(die_ranges(child, dwarfinfo))
                if child.tag in {"DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"}:
                    collect_inline_ranges(child)

        collect_inline_ranges(function_die)

        if binary_context is None:
            all_row_starts, all_row_locations = _line_program_rows(cu, line_program)
        else:
            all_row_starts, all_row_locations = _context_line_program_rows(
                binary_context,
                cu,
                line_program,
            )
        row_begin = bisect.bisect_left(all_row_starts, start)
        row_end = bisect.bisect_left(all_row_starts, end, lo=row_begin)
        row_starts = all_row_starts[row_begin:row_end]
        row_locations = all_row_locations[row_begin:row_end]

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
                    walk_scope(child, die_ranges(child, dwarfinfo, scope_ranges))
                    continue
                if child.tag not in {"DW_TAG_formal_parameter", "DW_TAG_variable"}:
                    continue
                name = _die_name(child)
                is_arg = child.tag == "DW_TAG_formal_parameter" and parent is function_die
                this_arg_index = arg_index if is_arg else None
                if is_arg:
                    arg_index += 1
                offsets = _location_offsets(child, dwarfinfo)
                token = re.compile(r"\b" + re.escape(name) + r"\b") if name else None
                addresses: set[int] = set()
                for address, location in address_location.items():
                    if scope_ranges and not any(
                        begin <= address < finish for begin, finish in scope_ranges
                    ):
                        continue
                    text = source_text.get(location)
                    if token is not None and text is not None and token.search(text):
                        addresses.add(address)
                raw_variables.append(
                    VariableEvidence(
                        identity=f"dwarf:0x{child.offset:x}",
                        addresses=frozenset(addresses),
                        stack_offsets=offsets,
                        arg_index=this_arg_index,
                    )
                )

        walk_scope(function_die, function_ranges)
        return raw_variables


def extract_decompiler_evidence(
    function: Any,
    *,
    backend: str,
    identity_prefix: str | None = None,
    include_unnamed: bool = False,
) -> list[VariableEvidence]:
    evidence_prefix = backend if identity_prefix is None else identity_prefix
    line_addresses = {
        int(mapping.line_number): frozenset(int(address) for address in mapping.addresses)
        for mapping in (getattr(function, "line_mappings", []) or [])
    }
    variables: list[VariableEvidence] = []
    for index, variable in enumerate(getattr(function, "variables", []) or []):
        if not variable.name and not include_unnamed:
            continue
        lines = {int(line) for line in getattr(variable, "line_numbers", [])}
        addresses = {int(address) for address in getattr(variable, "addresses", [])}
        if not addresses:
            addresses = {
                address for line in lines for address in line_addresses.get(line, frozenset())
            }
        stack_offsets = (int(variable.stack_offset),) if variable.stack_offset is not None else ()
        variables.append(
            VariableEvidence(
                identity=f"{evidence_prefix}:{index}",
                addresses=frozenset(addresses),
                stack_offsets=stack_offsets,
                arg_index=getattr(variable, "arg_index", None),
            )
        )
    return variables
