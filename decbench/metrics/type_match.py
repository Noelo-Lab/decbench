"""Type correctness metric.

Compares variable types in decompiled code against ground truth types
extracted from DWARF debug info in the original binary.

Based on the approach from decompiler-types-benchmark (SURE'25).
"""

from __future__ import annotations

import contextlib
import logging
import re
from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricResult, MetricValue

if TYPE_CHECKING:
    from pathlib import Path

    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult, FunctionDecompilation

logger = logging.getLogger(__name__)


# Type normalization: map common decompiler-specific types to standard C types
TYPE_MAP: dict[str, str] = {
    # angr types
    "undefined8": "long long",
    "undefined4": "int",
    "undefined2": "short",
    "undefined1": "char",
    "undefined": "char",
    # IDA types
    "__int64": "long long",
    "__int32": "int",
    "__int16": "short",
    "__int8": "char",
    "_QWORD": "long long",
    "_DWORD": "int",
    "_WORD": "short",
    "_BYTE": "char",
    "_BOOL": "bool",
    # kuna types (SLEIGH core-type spellings: intN/uintN are sized in BYTES,
    # matching the undefinedN convention above — int4 is a 4-byte int, int8 an
    # 8-byte int). Without these kuna's recovered types never normalize to the
    # DWARF base-type names and type_match is unfairly ~0, the same way angr's
    # undefinedN / IDA's __intN are aliased here.
    "int1": "char",
    "int2": "short",
    "int4": "int",
    "int8": "long long",
    "uint1": "char",
    "uint2": "short",
    "uint4": "int",
    "uint8": "long long",
    # Ghidra types
    "uint": "int",
    "ulong": "long long",
    # LP64: plain "long" is 8 bytes, same as DWARF "long int"/"long long"
    "long": "long long",
    "ushort": "short",
    "uchar": "char",
    "uint64_t": "long long",
    "uint32_t": "int",
    "uint16_t": "short",
    "uint8_t": "char",
    "int64_t": "long long",
    "int32_t": "int",
    "int16_t": "short",
    "int8_t": "char",
    "size_t": "long long",
    "ssize_t": "long long",
}

# Qualifiers to strip during normalization
QUALIFIERS = ["unsigned", "signed", "const", "volatile", "register", "static", "extern"]


def normalize_type(type_str: str) -> set[str]:
    """Normalize a type string to a set of equivalent representations.

    Returns multiple possible forms so that any intersection counts as a match.
    """
    if not type_str:
        return set()

    t = type_str.strip()

    # Apply TYPE_MAP first
    if t in TYPE_MAP:
        t = TYPE_MAP[t]

    forms = {t}

    # Strip qualifiers and generate normalized forms
    normalized = t
    for q in QUALIFIERS:
        normalized = normalized.replace(f"{q} ", "")
    normalized = normalized.strip()
    if normalized:
        forms.add(normalized)

    # Standard normalizations (DWARF base-type names like "short int" /
    # "long int" must converge with decompiler spellings like "short")
    for original, replacement in [
        ("long long int", "long long"),
        ("long int", "long long"),
        ("short int", "short"),
        ("_Bool", "bool"),
        ("Bool", "bool"),
        ("boolean", "bool"),
    ]:
        for form in list(forms):
            if original in form:
                forms.add(form.replace(original, replacement))

    # Remove whitespace variations
    forms = {re.sub(r"\s+", " ", f).strip() for f in forms if f.strip()}

    # Canonicalize pointer spacing ("char * *" / "char **" -> "char**")
    forms |= {re.sub(r"\s*\*", "*", f) for f in forms}

    # Re-apply TYPE_MAP to derived forms (e.g. "unsigned long" -> "long" -> LP64
    # "long long") after qualifier stripping.
    forms |= {TYPE_MAP[f] for f in forms if f in TYPE_MAP}

    return forms


def extract_ground_truth_types(binary_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Extract ground truth variable types from DWARF debug info.

    Works for **ELF and PE** binaries (the PE/MinGW malware targets) — the DWARF
    is read via :func:`decbench.utils.binfmt.dwarf_info`, which handles PE's
    string-table-encoded section names. The DIE-walking below is format-agnostic.

    Args:
        binary_path: Path to an ELF or PE binary compiled with -g

    Returns:
        Dict mapping function_name -> list of variable dicts with:
            - name: variable name
            - type: list of normalized type strings
            - rbp_offset: list of stack offsets
            - size: byte size
    """
    from decbench.utils import binfmt

    result: dict[str, list[dict[str, Any]]] = {}

    try:
        dwarfinfo = binfmt.dwarf_info(binary_path)
        if dwarfinfo is None:
            logger.debug("No DWARF info in %s", binary_path)
            return result

        for CU in dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            for DIE in top_DIE.iter_children():
                if DIE.tag != "DW_TAG_subprogram":
                    continue

                func_name, variables = _parse_function_die(DIE, dwarfinfo)
                if func_name and variables:
                    result[func_name] = variables

    except Exception as e:
        logger.warning("Failed to extract DWARF types from %s: %s", binary_path, e)

    return result


def _parse_function_die(die: Any, dwarfinfo: Any) -> tuple[str | None, list[dict[str, Any]]]:
    """Parse a DW_TAG_subprogram DIE to extract function variable types."""
    if "DW_AT_name" not in die.attributes:
        return None, []

    func_name = die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
    variables: list[dict[str, Any]] = []

    arg_index = 0
    for child in die.iter_children():
        if child.tag in ("DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"):
            variables.extend(_parse_lexical_block(child, dwarfinfo))
        elif child.tag == "DW_TAG_formal_parameter":
            var = _parse_variable_die(child, dwarfinfo, is_arg=True, arg_index=arg_index)
            # The positional index must reflect declaration order even when
            # an argument is dropped (e.g. fully optimized out).
            arg_index += 1
            if var:
                variables.append(var)
        elif child.tag == "DW_TAG_variable":
            var = _parse_variable_die(child, dwarfinfo)
            if var:
                variables.append(var)

    return func_name, variables


def _parse_lexical_block(die: Any, dwarfinfo: Any) -> list[dict[str, Any]]:
    """Recursively parse lexical blocks for variables."""
    variables: list[dict[str, Any]] = []
    for child in die.iter_children():
        if child.tag == "DW_TAG_lexical_block":
            variables.extend(_parse_lexical_block(child, dwarfinfo))
        elif child.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
            var = _parse_variable_die(child, dwarfinfo)
            if var:
                variables.append(var)
    return variables


def _parse_variable_die(
    die: Any,
    dwarfinfo: Any,
    is_arg: bool = False,
    arg_index: int | None = None,
) -> dict[str, Any] | None:
    """Parse a variable DIE to extract type info.

    Variables that have ANY DWARF location (stack OR register) are kept:
    at -O2 most locals/args live in registers (loclists with ``DW_OP_reg*``)
    and have no ``DW_OP_fbreg`` stack offset, but they still exist at runtime
    and decompilers are expected to recover them. Only variables without a
    location (fully optimized out) are dropped.
    """
    offsets, has_location = _get_location(die, dwarfinfo)
    if not has_location:
        return None

    # Follow abstract origin if present
    if "DW_AT_abstract_origin" in die.attributes:
        try:
            attr = die.attributes["DW_AT_abstract_origin"]
            die = dwarfinfo.get_DIE_from_refaddr(attr.value + die.cu.cu_offset)
        except Exception:
            pass

    name = ""
    if "DW_AT_name" in die.attributes:
        name = die.attributes["DW_AT_name"].value.decode("utf-8", "replace")

    type_names: list[str] = []
    size = 0

    with contextlib.suppress(Exception):
        type_names, size = _parse_type_die(die, dwarfinfo)

    if not type_names:
        return None

    # Normalize types
    all_forms: set[str] = set()
    for t in type_names:
        all_forms.update(normalize_type(t))

    return {
        "name": name,
        "type": list(all_forms),
        "rbp_offset": list(set(offsets)),
        "size": size,
        "is_arg": is_arg,
        "arg_index": arg_index if is_arg else None,
    }


def _get_location(die: Any, dwarfinfo: Any) -> tuple[list[int], bool]:
    """Extract location info from DW_AT_location.

    Returns:
        Tuple of (stack offsets from DW_OP_fbreg expressions, whether the
        variable has ANY location at all). Register-resident variables (the
        common case at -O2) yield ``([], True)``; fully optimized-out
        variables yield ``([], False)``.
    """
    from elftools.dwarf.dwarf_expr import DWARFExprParser

    offsets: list[int] = []
    has_location = False

    if "DW_AT_location" not in die.attributes:
        return offsets, has_location

    loc_attr = die.attributes["DW_AT_location"]
    expr_parser = DWARFExprParser(dwarfinfo.structs)

    try:
        if loc_attr.form == "DW_FORM_exprloc":
            ops = expr_parser.parse_expr(loc_attr.value)
            if ops:
                has_location = True
            for op in ops:
                if op.op_name == "DW_OP_fbreg":
                    offsets.append(op.args[0] + 16)

        elif loc_attr.form == "DW_FORM_sec_offset":
            loclists = dwarfinfo.location_lists()
            loclist = loclists.get_location_list_at_offset(loc_attr.value, die=die)

            for entry in loclist:
                expr = getattr(entry, "loc_expr", None) or getattr(entry, "location_expr", None)
                if expr is None:
                    continue
                ops = expr_parser.parse_expr(expr)
                if ops:
                    has_location = True
                if len(ops) != 1:
                    continue
                for op in ops:
                    if op.op_name == "DW_OP_fbreg":
                        offsets.append(op.args[0] + 16)
    except Exception:
        pass

    return offsets, has_location


def _parse_type_die(die: Any, dwarfinfo: Any) -> tuple[list[str], int]:
    """Recursively parse type DIEs to extract type name(s) and size."""
    if "DW_AT_type" not in die.attributes:
        return ["void"], 0

    attr = die.attributes["DW_AT_type"]
    type_offset = attr.value + die.cu.cu_offset
    type_die = dwarfinfo.get_DIE_from_refaddr(type_offset)
    tag = type_die.tag

    if tag == "DW_TAG_base_type":
        name = ""
        if "DW_AT_name" in type_die.attributes:
            name = type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
        size = type_die.attributes.get("DW_AT_byte_size", None)
        size = size.value if size else 0
        return [name] if name else ["void"], size

    elif tag == "DW_TAG_typedef":
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace"))
        child_names, size = _parse_type_die(type_die, dwarfinfo)
        names.extend(child_names)
        return names, size

    elif tag == "DW_TAG_pointer_type":
        child_names, _ = _parse_type_die(type_die, dwarfinfo)
        if not child_names:
            child_names = ["void"]
        ptr_names = [n + "*" for n in child_names]
        size = 8
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return ptr_names, size

    elif tag == "DW_TAG_array_type":
        child_names, elem_size = _parse_type_die(type_die, dwarfinfo)
        dims = _get_array_dims(type_die)
        length = dims[0] if dims and dims[0] else 1
        arr_names = [f"{n}[{length}]" for n in child_names]
        return child_names + arr_names, elem_size * length

    elif tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _parse_type_die(type_die, dwarfinfo)

    elif tag == "DW_TAG_structure_type":
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace"))
        if not names:
            names = ["struct"]
        size = 0
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return names, size

    elif tag in ("DW_TAG_union_type", "DW_TAG_class_type"):
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace"))
        if not names:
            names = ["union"]
        size = 0
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return names, size

    elif tag == "DW_TAG_enumeration_type":
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace"))
        names.append("int")
        size = 4
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return names, size

    elif tag == "DW_TAG_subroutine_type":
        return ["FUNCTION"], 0

    return ["void"], 0


def _get_array_dims(die: Any) -> list[int | None]:
    """Extract array dimensions from type DIE."""
    dims: list[int | None] = []
    try:
        for sub in die.iter_children():
            if sub.tag == "DW_TAG_subrange_type":
                ub_attr = sub.attributes.get("DW_AT_upper_bound")
                lb_attr = sub.attributes.get("DW_AT_lower_bound")
                lb = lb_attr.value if lb_attr else 0
                ub = ub_attr.value if ub_attr else None
                count = ub - lb + 1 if ub is not None else None
                dims.append(count)
    except Exception:
        pass
    return dims


def extract_types_from_decompiled_code(code: str) -> list[dict[str, Any]]:
    """Extract variable declarations and their types from decompiled C code.

    Uses regex-based parsing to find variable declarations.
    Returns list of dicts with 'name' and 'type' fields.
    """
    variables: list[dict[str, Any]] = []

    # Match common C variable declaration patterns
    # Handles: type name; type name = ...; type *name; type name[N];
    decl_pattern = re.compile(
        r"^\s*"
        r"((?:(?:unsigned|signed|const|volatile|static|struct|union|enum)\s+)*"
        r"(?:(?:long\s+long|long|short|int|char|float|double|void|bool|"
        r"__int\d+|_DWORD|_QWORD|_WORD|_BYTE|_BOOL|"
        r"u?int\d+_t|size_t|ssize_t|"
        r"undefined\d?|ulong|uint|ushort|uchar|"
        r"\w+_t)\s*\**)"  # type with possible pointer
        r")"
        r"\s+"
        r"(\w+)"  # variable name
        r"\s*(?:\[[^\]]*\])?"  # optional array
        r"\s*(?:=[^;]*)?"  # optional initializer
        r"\s*;",  # semicolon
        re.MULTILINE,
    )

    for match in decl_pattern.finditer(code):
        type_str = match.group(1).strip()
        var_name = match.group(2).strip()

        # Skip function-like names and common C keywords
        if var_name in ("if", "else", "while", "for", "return", "switch", "case", "break"):
            continue

        variables.append(
            {
                "name": var_name,
                "type": list(normalize_type(type_str)),
            }
        )

    return variables


def _calibrate_shift(gt_offsets: list[int], decomp_offsets: list[int]) -> int | None:
    """Find an additive shift aligning decompiled offsets to ground-truth offsets.

    Searches shifts ``k`` in ``range(-32, 33)`` (ties broken toward the smallest
    ``|k|``) maximizing the count of decompiled offsets ``d`` where ``d + k`` is a
    ground-truth offset. To avoid spurious single-variable alignments: if a nonzero
    ``k`` is best and there are at least 2 decompiled offsets, that ``k`` must align
    at least 2 offsets; otherwise fall back to ``k = 0`` if it aligns at least 1,
    else return ``None``.

    Args:
        gt_offsets: Ground-truth stack offsets.
        decomp_offsets: Decompiled (declib-lifted) stack offsets.

    Returns:
        The best shift ``k``, or ``None`` if no shift aligns anything.
    """
    if not gt_offsets or not decomp_offsets:
        return None

    gt_set = set(gt_offsets)

    best_k: int | None = None
    best_count = 0
    # Iterate by increasing |k| so ties resolve toward the smallest magnitude.
    for k in sorted(range(-32, 33), key=lambda x: (abs(x), x)):
        # Count UNIQUE ground-truth offsets matched so duplicate decompiled
        # slots cannot inflate a spurious shift.
        count = len({d + k for d in decomp_offsets} & gt_set)
        if count > best_count:
            best_count = count
            best_k = k

    if best_k is None or best_count == 0:
        return None

    # Guard against spurious single-variable alignments at a nonzero shift.
    if best_k != 0 and len(decomp_offsets) >= 2 and best_count < 2:
        zero_count = len(set(decomp_offsets) & gt_set)
        return 0 if zero_count >= 1 else None

    return best_k


def _calibrate_shift_multi(
    pairs: list[tuple[list[int], list[int]]],
) -> int | None:
    """Calibrate one additive shift across many functions' offset sets.

    Each pair is ``(gt_offsets, decomp_offsets)`` for one function. For a
    candidate shift, a function votes with ``max(0, unique_matches - 1)`` so
    that a lone slot coincidentally aligning somewhere contributes nothing,
    while multi-variable alignments (real ABI-constant shifts) accumulate.
    Falls back to plain unique-match counting when no shift earns a
    discounted vote (e.g. every function has a single stack variable).

    Args:
        pairs: Per-function (ground-truth offsets, decompiled offsets).

    Returns:
        The best shift, or ``None`` if nothing aligns at all.
    """
    pairs = [(g, d) for g, d in pairs if g and d]
    if not pairs:
        return None

    candidates = sorted(range(-32, 33), key=lambda x: (abs(x), x))

    def matches(gt_offs: list[int], dec_offs: list[int], k: int) -> int:
        return len({d + k for d in dec_offs} & set(gt_offs))

    best_k: int | None = None
    best_votes = 0
    for k in candidates:
        votes = sum(max(0, matches(g, d, k) - 1) for g, d in pairs)
        if votes > best_votes:
            best_votes = votes
            best_k = k

    if best_k is not None:
        return best_k

    # Fallback: no multi-variable signal anywhere; use plain unique counts,
    # guarded against electing a shift from single-slot coincidences.
    for k in candidates:
        votes = sum(matches(g, d, k) for g, d in pairs)
        if votes > best_votes:
            best_votes = votes
            best_k = k

    if best_k is None or best_votes == 0:
        return None
    if best_k != 0:
        # Prefer no shift whenever it aligns anything; otherwise require a
        # nonzero shift to be supported by more than one coincidence.
        zero_votes = sum(matches(g, d, 0) for g, d in pairs)
        if zero_votes >= 1:
            return 0
        if best_votes < 2:
            return None
    return best_k


@register_metric("type_match")
class TypeMatchMetric(Metric):
    """Type correctness metric.

    Compares variable types in decompiled code against ground truth
    DWARF debug info from the original binary. For each function,
    computes the accuracy as: TP / (TP + FP + FN) where
    - TP: variable at matching offset with matching type
    - FP: variable at matching offset with wrong type
    - FN: ground truth variable not found in decompilation

    Perfect score is 1.0 (all types match).
    """

    name = "type_match"
    display_name = "Type Correctness"
    description = "Accuracy of variable type recovery vs DWARF ground truth"

    weight = 1.0
    lower_is_better = False
    perfect_value = 1.0
    default_aggregation = AggregationType.PERCENT

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)
        self._ground_truth_cache: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        ground_truth_vars: list[dict[str, Any]] | None = None,
        calibration_shift: int | None = None,
        **kwargs: Any,
    ) -> MetricValue:
        """Compute type match accuracy for a single function.

        When the decompiled function exposes structured variables, matching
        proceeds in three passes (each decompiled variable credited at most
        once):

        1. Arguments by ABI position: DWARF formal parameters (in declaration
           order) vs decompiled arguments (by index). Position is a reliable
           identity even when names are synthetic (angr) and offsets are
           absent (registers at -O2).
        2. Stack variables by calibrated offset.
        3. Everything else by exact name (covers register-resident locals
           when the decompiler imported debug names, and stack slots promoted
           to args/registers).

        Without structured variables, falls back to regex parsing of the
        decompiled text and name matching.

        Args:
            decompiled: The decompiled function.
            ground_truth_vars: Ground truth variables from DWARF.
            calibration_shift: Pre-computed offset shift (e.g. calibrated
                across the whole binary). When ``None``, the shift is
                calibrated from this function's offsets alone.
        """
        if not ground_truth_vars:
            return MetricValue(
                value=0.0,
                metadata={"error": "No ground truth types available"},
            )

        # The type-match value is fully determined by the decompiled variables,
        # the DWARF ground-truth variables, and the calibration shift. Cache on
        # those (the decompiled code is included so the regex fallback path is
        # also keyed correctly).
        key_inputs = [
            [
                {
                    "name": v.name,
                    "type": v.type,
                    "stack_offset": v.stack_offset,
                    "size": v.size,
                    "kind": getattr(v, "kind", None),
                    "arg_index": v.arg_index,
                }
                for v in decompiled.variables
            ],
            decompiled.decompiled_code if not decompiled.variables else "",
            ground_truth_vars,
            calibration_shift,
        ]
        return self._cached_value(
            key_inputs,
            lambda: self._compute_uncached(decompiled, ground_truth_vars, calibration_shift),
        )

    def _compute_uncached(
        self,
        decompiled: FunctionDecompilation,
        ground_truth_vars: list[dict[str, Any]],
        calibration_shift: int | None,
    ) -> MetricValue:
        gt_stack_vars = sum(1 for gv in ground_truth_vars if gv.get("rbp_offset"))
        decomp_stack_vars = sum(1 for v in decompiled.variables if v.stack_offset is not None)

        if decompiled.variables:
            return self._match_structured(
                decompiled,
                ground_truth_vars,
                gt_stack_vars,
                decomp_stack_vars,
                calibration_shift,
            )

        return self._match_by_regex(decompiled, ground_truth_vars, gt_stack_vars, decomp_stack_vars)

    @staticmethod
    def _build_result(
        tp: int,
        fp: int,
        fn: int,
        ground_truth_vars: list[dict[str, Any]],
        decomp_vars: int,
        matched_by: str,
        calibration_shift: int | None,
        gt_stack_vars: int,
        decomp_stack_vars: int,
        extra_metadata: dict[str, Any] | None = None,
    ) -> MetricValue:
        """Assemble a MetricValue with the standard metadata payload."""
        total = tp + fp + fn
        accuracy = tp / total if total > 0 else 0.0
        metadata: dict[str, Any] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "gt_vars": len(ground_truth_vars),
            "decomp_vars": decomp_vars,
            "matched_by": matched_by,
            "calibration_shift": calibration_shift,
            "gt_stack_vars": gt_stack_vars,
            "decomp_stack_vars": decomp_stack_vars,
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        return MetricValue(
            value=accuracy,
            raw_value=accuracy,
            metadata=metadata,
        )

    def _match_structured(
        self,
        decompiled: FunctionDecompilation,
        ground_truth_vars: list[dict[str, Any]],
        gt_stack_vars: int,
        decomp_stack_vars: int,
        calibration_shift: int | None = None,
    ) -> MetricValue:
        """Match GT vars to structured decompiled vars: arg position, then
        stack offset, then name. Each decompiled variable is credited at most
        once (DWARF can report more variables at an offset/name than the
        decompiler recovered, e.g. shadowed locals)."""
        if calibration_shift is not None:
            shift: int | None = calibration_shift
        else:
            gt_offsets: list[int] = []
            for gv in ground_truth_vars:
                gt_offsets.extend(gv.get("rbp_offset", []))

            decomp_offsets = [
                v.stack_offset for v in decompiled.variables if v.stack_offset is not None
            ]

            shift = _calibrate_shift(gt_offsets, decomp_offsets)

        k = shift if shift is not None else 0

        var_types: list[set[str]] = [normalize_type(v.type) for v in decompiled.variables]
        by_arg_index: dict[int, int] = {}
        by_off: dict[int, list[int]] = {}
        by_name: dict[str, list[int]] = {}
        for i, v in enumerate(decompiled.variables):
            if v.arg_index is not None and v.arg_index not in by_arg_index:
                by_arg_index[v.arg_index] = i
            if v.stack_offset is not None:
                by_off.setdefault(v.stack_offset + k, []).append(i)
            if v.name:
                by_name.setdefault(v.name, []).append(i)

        used: set[int] = set()

        def claim(candidates: list[int], gt_types: set[str]) -> bool | None:
            """Claim the best unused candidate: True=tp, False=fp, None=miss."""
            avail = [i for i in candidates if i not in used]
            if not avail:
                return None
            hit = next((i for i in avail if gt_types & var_types[i]), None)
            if hit is not None:
                used.add(hit)
                return True
            used.add(avail[0])
            return False

        n = len(ground_truth_vars)
        verdicts: list[bool | None] = [None] * n
        decided: list[bool] = [False] * n
        pass_counts = {"arg": 0, "offset": 0, "name": 0}

        # Pass 1: arguments by ABI position. Position is a reliable identity
        # even with synthetic names (angr) and register args (-O2).
        for gi, gv in enumerate(ground_truth_vars):
            arg_index = gv.get("arg_index")
            if not gv.get("is_arg") or arg_index is None:
                continue
            di = by_arg_index.get(arg_index)
            if di is None or di in used:
                continue
            used.add(di)
            decided[gi] = True
            verdicts[gi] = bool(set(gv.get("type", [])) & var_types[di])
            pass_counts["arg"] += 1

        # Pass 2: stack variables by calibrated offset (any-of across the
        # DWARF loclist offsets).
        for gi, gv in enumerate(ground_truth_vars):
            if decided[gi]:
                continue
            candidates: list[int] = []
            for off in gv.get("rbp_offset", []):
                candidates.extend(by_off.get(off, []))
            if not candidates:
                continue
            verdict = claim(candidates, set(gv.get("type", [])))
            if verdict is not None:
                decided[gi] = True
                verdicts[gi] = verdict
                pass_counts["offset"] += 1

        # Pass 3: names. Covers register-resident locals when the decompiler
        # imported debug names, and stack slots promoted to args/registers.
        for gi, gv in enumerate(ground_truth_vars):
            if decided[gi]:
                continue
            gt_name = gv.get("name", "")
            if not gt_name:
                continue
            verdict = claim(by_name.get(gt_name, []), set(gv.get("type", [])))
            if verdict is not None:
                decided[gi] = True
                verdicts[gi] = verdict
                pass_counts["name"] += 1

        tp = sum(1 for d, v in zip(decided, verdicts, strict=True) if d and v)
        fp = sum(1 for d, v in zip(decided, verdicts, strict=True) if d and not v)
        fn = sum(1 for d in decided if not d)

        return self._build_result(
            tp,
            fp,
            fn,
            ground_truth_vars,
            len(decompiled.variables),
            "structured",
            shift,
            gt_stack_vars,
            decomp_stack_vars,
            extra_metadata={
                "matched_by_arg": pass_counts["arg"],
                "matched_by_offset": pass_counts["offset"],
                "matched_by_name": pass_counts["name"],
                "gt_arg_vars": sum(1 for gv in ground_truth_vars if gv.get("is_arg")),
            },
        )

    def _match_by_regex(
        self,
        decompiled: FunctionDecompilation,
        ground_truth_vars: list[dict[str, Any]],
        gt_stack_vars: int,
        decomp_stack_vars: int,
    ) -> MetricValue:
        """Match GT vars to regex-extracted decompiled declarations by name."""
        decomp_vars = extract_types_from_decompiled_code(decompiled.decompiled_code)

        if not decomp_vars:
            fn = len(ground_truth_vars)
            return self._build_result(
                0,
                0,
                fn,
                ground_truth_vars,
                0,
                "regex",
                None,
                gt_stack_vars,
                decomp_stack_vars,
            )

        type_by_name: dict[str, set[str]] = {}
        for var in decomp_vars:
            type_by_name.setdefault(var["name"], set()).update(var["type"])

        tp = 0
        fp = 0
        fn = 0

        for gt_var in ground_truth_vars:
            gt_name = gt_var.get("name", "")
            gt_types = set(gt_var.get("type", []))
            if gt_name in type_by_name:
                if gt_types.intersection(type_by_name[gt_name]):
                    tp += 1
                else:
                    fp += 1
            else:
                fn += 1

        return self._build_result(
            tp,
            fp,
            fn,
            ground_truth_vars,
            len(decomp_vars),
            "regex",
            None,
            gt_stack_vars,
            decomp_stack_vars,
        )

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs: dict[str, DiGraph] | None = None,
        decompiled_cfgs: dict[str, DiGraph] | None = None,
        **kwargs: Any,
    ) -> MetricResult:
        """Compute type match for all functions, using DWARF ground truth."""
        import time

        start_time = time.time()
        function_results: dict[str, MetricValue] = {}
        errors: list[str] = []

        # Extract ground truth from the original binary
        binary_path = decompilation.binary_path
        cache_key = str(binary_path)

        if cache_key in self._ground_truth_cache:
            gt_types = self._ground_truth_cache[cache_key]
        else:
            gt_types = extract_ground_truth_types(binary_path)
            self._ground_truth_cache[cache_key] = gt_types

        if not gt_types:
            logger.warning(
                "No DWARF ground truth types for %s. " "Binary may not have been compiled with -g.",
                binary_path,
            )

        # Calibrate the GT<->decompiler offset shift once per binary: the
        # shift is an ABI/decompiler constant, and pooling offsets across all
        # functions makes calibration robust for functions with few stack
        # variables (where a lone slot could align to a spurious shift).
        binary_shift = self._calibrate_binary_shift(decompilation, gt_types)

        for func_name, func_decomp in decompilation.functions.items():
            try:
                gt_vars = gt_types.get(func_name, [])
                if not gt_vars:
                    continue

                value = self.compute_for_function(
                    func_decomp,
                    ground_truth_vars=gt_vars,
                    calibration_shift=binary_shift,
                )
                function_results[func_name] = value

            except Exception as e:
                errors.append(f"{func_name}: {str(e)}")

        # Diagnostic: GT existed but nothing matched across all functions.
        if gt_types and (
            not function_results or all(v.value == 0.0 for v in function_results.values())
        ):
            total_gt_vars = sum(len(v) for v in gt_types.values())
            total_gt_stack_vars = sum(
                1 for vs in gt_types.values() for gv in vs if gv.get("rbp_offset")
            )
            logger.warning(
                "type_match scored 0 for all matched functions in %s "
                "(gt_funcs=%d, gt_vars=%d, gt_stack_vars=%d). Likely causes: "
                "(a) the decompiler produced no structured variables "
                "(arguments/stack vars) to align positionally or by offset; "
                "(b) variable names/offsets/types did not align between DWARF "
                "and the decompiler output.",
                binary_path,
                len(gt_types),
                total_gt_vars,
                total_gt_stack_vars,
            )

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

    @staticmethod
    def _calibrate_binary_shift(
        decompilation: DecompilationResult,
        gt_types: dict[str, list[dict[str, Any]]],
    ) -> int | None:
        """Calibrate the offset shift across all functions of a binary.

        Gathers per-function (ground-truth, decompiled) stack offset sets and
        finds the single additive shift that aligns them best across the
        binary. Returns ``None`` when there is nothing to calibrate against.
        """
        pairs: list[tuple[list[int], list[int]]] = []

        for func_name, func_decomp in decompilation.functions.items():
            gt_vars = gt_types.get(func_name, [])
            if not gt_vars:
                continue
            func_gt = [o for gv in gt_vars for o in gv.get("rbp_offset", [])]
            func_dec = [v.stack_offset for v in func_decomp.variables if v.stack_offset is not None]
            if func_gt and func_dec:
                pairs.append((func_gt, func_dec))

        return _calibrate_shift_multi(pairs)
