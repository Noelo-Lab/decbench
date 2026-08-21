"""Address- and usage-evidence matching for local-variable correspondence."""

from __future__ import annotations

import bisect
import contextlib
import math
import re
import struct
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Literal


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
    usage_features: tuple[tuple[str, int], ...] = ()
    inferred_from_code: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["addresses"] = [f"0x{x:x}" for x in sorted(self.addresses)]
        data["stack_offsets"] = list(self.stack_offsets)
        data["lines"] = list(self.lines)
        data["live_ranges"] = [[f"0x{start:x}", f"0x{end:x}"] for start, end in self.live_ranges]
        data["usage_features"] = {feature: count for feature, count in self.usage_features}
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VariableEvidence:
        """Load evidence emitted by :meth:`to_dict`."""

        def address(value: Any) -> int:
            return int(value, 0) if isinstance(value, str) else int(value)

        raw_features = data.get("usage_features", {})
        features = raw_features.items() if isinstance(raw_features, Mapping) else raw_features
        return cls(
            identity=str(data["identity"]),
            name=str(data.get("name", "")),
            addresses=frozenset(address(value) for value in data.get("addresses", [])),
            stack_offsets=tuple(int(value) for value in data.get("stack_offsets", [])),
            size=int(data["size"]) if data.get("size") is not None else None,
            kind=str(data.get("kind", "local")),
            arg_index=(int(data["arg_index"]) if data.get("arg_index") is not None else None),
            decl_file=(str(data["decl_file"]) if data.get("decl_file") is not None else None),
            decl_line=(int(data["decl_line"]) if data.get("decl_line") is not None else None),
            lines=tuple(int(value) for value in data.get("lines", [])),
            live_ranges=tuple(
                (address(start), address(end)) for start, end in data.get("live_ranges", [])
            ),
            usage_features=tuple(sorted((str(feature), int(count)) for feature, count in features)),
            inferred_from_code=bool(data.get("inferred_from_code", False)),
        )


@dataclass(frozen=True)
class VariableMatch:
    source_id: str
    decompiled_id: str
    stage: str
    score: float
    intersection: tuple[int, ...] = ()
    source_runner_up_gap: float | None = None
    decompiled_runner_up_gap: float | None = None

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

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FunctionEvidence:
        """Load evidence emitted by :meth:`to_dict`."""

        def address(value: Any) -> int:
            return int(value, 0) if isinstance(value, str) else int(value)

        return cls(
            name=str(data["name"]),
            start=address(data["start"]),
            end=address(data["end"]),
            variables=[VariableEvidence.from_dict(row) for row in data.get("variables", [])],
            code=str(data.get("code", "")),
            line_addresses={
                int(line): frozenset(address(value) for value in addresses)
                for line, addresses in data.get("line_addresses", {}).items()
            },
        )


@dataclass
class SourceBinaryEvidenceContext:
    stream: Any
    elf: Any
    dwarfinfo: Any
    functions: dict[tuple[str, int], tuple[Any, Any]]
    machine: Any
    text_address: int | None
    text_data: bytes | None
    line_rows: dict[
        int,
        tuple[tuple[int, ...], tuple[tuple[str, int] | None, ...]],
    ] = field(default_factory=dict)


def _size_compatible(
    source: VariableEvidence,
    decompiled: VariableEvidence,
    *,
    enabled: bool,
) -> bool:
    if not enabled:
        return True
    return source.size is None or decompiled.size is None or source.size == decompiled.size


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
    *,
    use_size_compatibility: bool,
) -> int | None:
    shifts = {
        source_offset - decompiled_offset
        for source_var in source
        for decompiled_var in decompiled
        if _size_compatible(
            source_var,
            decompiled_var,
            enabled=use_size_compatibility,
        )
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
                    if _size_compatible(
                        source_var,
                        decompiled_var,
                        enabled=use_size_compatibility,
                    ):
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


def _usage_weights(
    source: Iterable[VariableEvidence],
    decompiled: Iterable[VariableEvidence],
) -> dict[str, float]:
    from decbench.metrics.variable_features import feature_reliability

    degrees: dict[str, int] = defaultdict(int)
    for variable in [*source, *decompiled]:
        for feature, count in variable.usage_features:
            if count > 0:
                degrees[feature] += 1
    return {
        feature: feature_reliability(feature) / max(1.0, math.log2(degree + 1))
        for feature, degree in degrees.items()
    }


def _usage_similarity(
    source: VariableEvidence,
    decompiled: VariableEvidence,
    weights: Mapping[str, float],
) -> float:
    from decbench.metrics.variable_features import is_context_feature

    source_features = {feature: count for feature, count in source.usage_features if count > 0}
    decompiled_features = {
        feature: count for feature, count in decompiled.usage_features if count > 0
    }
    shared = source_features.keys() & decompiled_features.keys()
    if not any(is_context_feature(feature) for feature in shared):
        return 0.0
    union = source_features.keys() | decompiled_features.keys()
    numerator = sum(
        weights[feature]
        * min(
            math.log1p(source_features.get(feature, 0)),
            math.log1p(decompiled_features.get(feature, 0)),
        )
        for feature in union
    )
    denominator = sum(
        weights[feature]
        * max(
            math.log1p(source_features.get(feature, 0)),
            math.log1p(decompiled_features.get(feature, 0)),
        )
        for feature in union
    )
    return numerator / denominator if denominator else 0.0


def has_usage_context(variable: VariableEvidence) -> bool:
    """Return whether a variable has a non-generic feature usable for matching."""

    from decbench.metrics.variable_features import is_context_feature

    return any(
        count > 0 and is_context_feature(feature) for feature, count in variable.usage_features
    )


MatcherMode = Literal["address", "usage", "address+usage"]
MATCHER_MODES: tuple[MatcherMode, ...] = ("address", "usage", "address+usage")


def match_variables(
    source: Iterable[VariableEvidence],
    decompiled: Iterable[VariableEvidence],
    *,
    mode: MatcherMode = "address",
    min_overlap: float = 0.1,
    ambiguity_margin: float = 0.03,
    min_usage_similarity: float = 0.1,
    usage_ambiguity_margin: float = 0.03,
    min_combined_similarity: float = 0.1,
    combined_ambiguity_margin: float | None = None,
    address_weight: float = 0.5,
    use_size_compatibility: bool = False,
    stack_shift_hint: int | None = None,
) -> DistanceResult:
    if mode not in MATCHER_MODES:
        raise ValueError(f"unknown matcher mode {mode!r}; expected one of {MATCHER_MODES}")
    if not 0 < address_weight < 1:
        raise ValueError("address_weight must be strictly between 0 and 1")
    fused_margin = (
        usage_ambiguity_margin if combined_ambiguity_margin is None else combined_ambiguity_margin
    )
    if any(
        value < 0
        for value in (
            min_overlap,
            ambiguity_margin,
            min_usage_similarity,
            usage_ambiguity_margin,
            min_combined_similarity,
            fused_margin,
        )
    ):
        raise ValueError("matcher thresholds and ambiguity margins must be non-negative")
    source_all = sorted(source, key=lambda var: var.identity)
    decompiled_candidates: list[VariableEvidence] = []
    for variable in decompiled:
        if not variable.inferred_from_code:
            decompiled_candidates.append(variable)
            continue
        if mode == "usage":
            decompiled_candidates.append(variable)
            continue
        sanitized = replace(
            variable,
            addresses=frozenset(),
            lines=(),
            live_ranges=(),
            usage_features=() if mode == "address" else variable.usage_features,
        )
        if mode != "address" or sanitized.arg_index is not None or sanitized.stack_offsets:
            decompiled_candidates.append(sanitized)
    decompiled_all = sorted(decompiled_candidates, key=lambda var: var.identity)
    if mode == "address":
        observable = [
            var
            for var in source_all
            if var.addresses or var.stack_offsets or var.arg_index is not None
        ]
    elif mode == "usage":
        observable = [var for var in source_all if has_usage_context(var)]
    else:
        observable = [
            var
            for var in source_all
            if (
                var.addresses
                or var.stack_offsets
                or var.arg_index is not None
                or has_usage_context(var)
            )
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
        score: float,
        *,
        source_runner_up_gap: float | None = None,
        decompiled_runner_up_gap: float | None = None,
    ) -> None:
        intersection = (
            ()
            if mode == "usage"
            else tuple(
                sorted(
                    source_by_id[source_id].addresses & decompiled_by_id[decompiled_id].addresses
                )
            )
        )
        matches.append(
            VariableMatch(
                source_id,
                decompiled_id,
                stage,
                score,
                intersection,
                source_runner_up_gap,
                decompiled_runner_up_gap,
            )
        )
        remaining_source.remove(source_id)
        remaining_decompiled.remove(decompiled_id)

    use_anchors = mode != "usage"
    if use_anchors:
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

    source_stack = (
        [source_by_id[key] for key in remaining_source if source_by_id[key].stack_offsets]
        if use_anchors
        else []
    )
    decompiled_stack = (
        [
            decompiled_by_id[key]
            for key in remaining_decompiled
            if decompiled_by_id[key].stack_offsets
        ]
        if use_anchors
        else []
    )
    shift = (
        _stack_shift(
            source_stack,
            decompiled_stack,
            use_size_compatibility=use_size_compatibility,
        )
        if use_anchors
        else None
    )
    if shift is None and use_anchors:
        shift = stack_shift_hint
    if shift is not None:
        source_neighbors: dict[str, set[str]] = defaultdict(set)
        decompiled_neighbors: dict[str, set[str]] = defaultdict(set)
        for source_var in source_stack:
            for decompiled_var in decompiled_stack:
                if not _size_compatible(
                    source_var,
                    decompiled_var,
                    enabled=use_size_compatibility,
                ):
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
    address_weights = (
        _address_weights(remaining_source_vars, remaining_decompiled_vars)
        if mode != "usage"
        else {}
    )
    usage_weights = (
        _usage_weights(remaining_source_vars, remaining_decompiled_vars)
        if mode != "address"
        else {}
    )
    edges: dict[tuple[str, str], tuple[float, tuple[int, ...], str, float]] = {}
    for source_var in remaining_source_vars:
        for decompiled_var in remaining_decompiled_vars:
            address_score, intersection = (
                _weighted_dice(source_var, decompiled_var, address_weights)
                if mode != "usage"
                else (0.0, ())
            )
            usage_score = (
                _usage_similarity(source_var, decompiled_var, usage_weights)
                if mode != "address"
                else 0.0
            )
            if mode == "address":
                score = address_score
                threshold = min_overlap
                stage = "overlap"
                margin = ambiguity_margin
            elif mode == "usage":
                score = usage_score
                threshold = min_usage_similarity
                stage = "usage"
                margin = usage_ambiguity_margin
            else:
                address_available = bool(source_var.addresses and decompiled_var.addresses)
                usage_available = has_usage_context(source_var) and has_usage_context(
                    decompiled_var
                )
                if address_available and usage_available:
                    score = address_weight * address_score + (1 - address_weight) * usage_score
                    stage = "fused"
                    threshold = min_combined_similarity
                    margin = fused_margin
                elif address_available:
                    score = address_score
                    stage = "address-only"
                    threshold = min_overlap
                    margin = ambiguity_margin
                else:
                    score = usage_score
                    stage = "usage-fallback"
                    threshold = min_usage_similarity
                    margin = usage_ambiguity_margin
            if score >= threshold and (mode == "address" or score > 0):
                edges[(source_var.identity, decompiled_var.identity)] = (
                    score,
                    intersection,
                    stage,
                    margin,
                )

    candidates: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for (source_id, decompiled_id), (score, _intersection, _stage, _margin) in edges.items():
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
        for (source_id, decompiled_id), (
            score,
            _intersection,
            _stage,
            _margin,
        ) in active.items():
            source_rank[source_id].append((decompiled_id, score))
            decompiled_rank[decompiled_id].append((source_id, score))
        for rows in source_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))
        for rows in decompiled_rank.values():
            rows.sort(key=lambda row: (-row[1], row[0]))

        accepted = False
        for (source_id, decompiled_id), (score, _intersection, stage, margin) in sorted(
            active.items(),
            key=lambda row: (-row[1][0], row[0][0], row[0][1]),
        ):
            source_rows = source_rank[source_id]
            decompiled_rows = decompiled_rank[decompiled_id]
            if source_rows[0][0] != decompiled_id or decompiled_rows[0][0] != source_id:
                continue
            source_gap = score - source_rows[1][1] if len(source_rows) > 1 else None
            decompiled_gap = score - decompiled_rows[1][1] if len(decompiled_rows) > 1 else None
            gaps = (source_gap, decompiled_gap)
            ambiguous = (
                any(gap is not None and gap < margin for gap in gaps)
                if mode == "address"
                else any(gap is not None and gap <= margin for gap in gaps)
            )
            if ambiguous:
                continue
            accept(
                source_id,
                decompiled_id,
                stage,
                score,
                source_runner_up_gap=source_gap,
                decompiled_runner_up_gap=decompiled_gap,
            )
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
    from decbench.utils.binfmt import die_str_attr

    return die_str_attr(die, "DW_AT_name") or ""


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


def open_source_binary_context(binary_path: Path) -> SourceBinaryEvidenceContext:
    from elftools.elf.elffile import ELFFile

    stream = binary_path.open("rb")
    try:
        elf = ELFFile(stream)
        dwarfinfo = elf.get_dwarf_info()
        text = elf.get_section_by_name(".text")
        text_address = int(text["sh_addr"]) if text is not None else None
        text_data = text.data() if text is not None else None
        functions: dict[tuple[str, int], tuple[Any, Any]] = {}
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name = _die_name(die)
                if not name:
                    continue
                for begin, _end in _die_ranges(die, dwarfinfo):
                    functions.setdefault((name, begin), (cu, die))
    except Exception:
        stream.close()
        raise
    return SourceBinaryEvidenceContext(
        stream,
        elf,
        dwarfinfo,
        functions,
        elf["e_machine"],
        text_address,
        text_data,
    )


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
        begin = getattr(entry, "begin_offset", None)
        end = getattr(entry, "end_offset", None)
        if begin is None or end is None:
            continue
        if getattr(entry, "is_absolute", False):
            live_ranges.append((int(begin), int(end)))
        else:
            live_ranges.append((base + int(begin), base + int(end)))
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


def _line_program_rows(
    cu: Any,
    line_program: Any,
) -> tuple[tuple[int, ...], tuple[tuple[str, int] | None, ...]]:
    rows: dict[int, tuple[str, int] | None] = {}
    entries = line_program.header["file_entry"]
    for entry in line_program.get_entries():
        state = entry.state
        if state is None or state.end_sequence:
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
    elf: Any,
    start: int,
    end: int,
    binary_context: SourceBinaryEvidenceContext | None = None,
) -> list[int]:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    machine = binary_context.machine if binary_context is not None else elf["e_machine"]
    if machine != "EM_X86_64" and machine != "EM_386":
        raise ValueError(f"unsupported demo architecture {machine}")
    if binary_context is None:
        text = elf.get_section_by_name(".text")
        if text is None:
            return []
        text_address = int(text["sh_addr"])
        text_data = text.data()
    else:
        text_address = binary_context.text_address
        text_data = binary_context.text_data
        if text_address is None or text_data is None:
            return []
    offset = start - text_address
    code = text_data[offset : offset + (end - start)]
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
    source_lines: Mapping[tuple[str, int], str] | None = None,
    feature_code: str | None = None,
    binary_context: SourceBinaryEvidenceContext | None = None,
) -> FunctionEvidence:
    from elftools.elf.elffile import ELFFile

    source_text = (
        source_lines
        if source_lines is not None
        else load_source_lines(source_path, preprocessed_path)
    )
    with contextlib.ExitStack() as stack:
        if binary_context is None:
            stream = stack.enter_context(binary_path.open("rb"))
            elf = ELFFile(stream)
            dwarfinfo = elf.get_dwarf_info()
        else:
            elf = binary_context.elf
            dwarfinfo = binary_context.dwarfinfo
        found = (
            binary_context.functions.get((function_name, function_address))
            if binary_context is not None and function_address is not None
            else None
        )
        for cu in dwarfinfo.iter_CUs():
            if found is not None:
                break
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
        if line_program is None:
            raise ValueError(f"DWARF function {function_name!r} has no line program")
        function_ranges = _die_ranges(function_die, dwarfinfo)
        if not function_ranges:
            raise ValueError(f"DWARF function {function_name!r} has no address range")
        start = min(begin for begin, _end in function_ranges)
        end = max(finish for _begin, finish in function_ranges)
        instructions = instruction_addresses(elf, start, end, binary_context)
        inline_ranges: list[tuple[int, int]] = []

        def collect_inline_ranges(parent: Any) -> None:
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine":
                    inline_ranges.extend(_die_ranges(child, dwarfinfo))
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
        from decbench.metrics.variable_features import (
            analyze_c_function,
            extract_c_function,
        )

        selected_code = feature_code
        if selected_code is None:
            selected_code = extract_c_function(
                source_path.read_text(errors="replace"),
                function_name,
            )
        if selected_code is not None:
            analysis = analyze_c_function(
                selected_code,
                function_name,
                (variable.name for variable in raw_variables),
            )
            raw_variables = [
                replace(
                    variable,
                    usage_features=analysis.features.get(variable.name, ()),
                )
                for variable in raw_variables
            ]
        line_addresses: dict[int, set[int]] = defaultdict(set)
        for address, (_filename, line) in address_location.items():
            line_addresses[line].add(address)
        return FunctionEvidence(
            function_name,
            start,
            end,
            raw_variables,
            code=selected_code or "",
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

    from decbench.metrics.variable_features import analyze_c_function

    analysis = analyze_c_function(
        "\n".join(lines),
        function_name,
        (variable.name for variable in variables),
    )
    variables = [
        replace(
            variable,
            usage_features=analysis.features.get(variable.name, ()),
        )
        for variable in variables
    ]

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
    identity_prefix: str | None = None,
    function_name: str | None = None,
    function_end: int | None = None,
    include_unnamed: bool = False,
    infer_code_variables: bool = True,
) -> FunctionEvidence:
    from decbench.metrics.variable_features import analyze_c_function

    base_backend = backend.split("@", 1)[0]
    evidence_prefix = backend if identity_prefix is None else identity_prefix
    line_addresses = {
        int(mapping.line_number): frozenset(int(address) for address in mapping.addresses)
        for mapping in (getattr(function, "line_mappings", []) or [])
    }
    code_lines = function.decompiled_code.splitlines()
    structured = list(getattr(function, "variables", []) or [])
    analysis = analyze_c_function(
        function.decompiled_code,
        function.name,
        (variable.name for variable in structured) if structured else None,
    )
    variables: list[VariableEvidence] = []
    if structured:
        for index, variable in enumerate(structured):
            if not variable.name and not include_unnamed:
                continue
            lines = {int(line) for line in getattr(variable, "line_numbers", [])}
            if variable.name and not lines and base_backend not in {"ida", "ghidra"}:
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
            stack_offsets = (
                (int(variable.stack_offset),) if variable.stack_offset is not None else ()
            )
            variables.append(
                VariableEvidence(
                    identity=f"{evidence_prefix}:{index}",
                    name=variable.name,
                    addresses=frozenset(addresses),
                    stack_offsets=stack_offsets,
                    size=getattr(variable, "size", None),
                    kind="arg" if getattr(variable, "kind", "") == "arg" else "local",
                    arg_index=getattr(variable, "arg_index", None),
                    lines=tuple(sorted(lines)),
                    usage_features=analysis.features.get(variable.name, ()),
                )
            )
    elif infer_code_variables:
        for index, variable in enumerate(analysis.variables):
            variables.append(
                VariableEvidence(
                    identity=f"{evidence_prefix}:inferred:{index}",
                    name=variable.name,
                    kind=variable.kind,
                    arg_index=variable.arg_index,
                    usage_features=analysis.features.get(variable.name, ()),
                    inferred_from_code=True,
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
