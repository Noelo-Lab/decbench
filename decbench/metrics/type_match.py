"""Type correctness metric.

Compares variable types in decompiled code against ground truth types
extracted from DWARF debug info in the original binary.

Based on the approach from decompiler-types-benchmark (SURE'25).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricResult, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph
    from pathlib import Path

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
    # Ghidra types
    "uint": "int",
    "ulong": "long long",
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

    # Standard normalizations
    for original, replacement in [
        ("long long int", "long long"),
        ("long int", "long long"),
        ("_Bool", "bool"),
        ("Bool", "bool"),
        ("boolean", "bool"),
    ]:
        for form in list(forms):
            if original in form:
                forms.add(form.replace(original, replacement))

    # Remove whitespace variations
    forms = {re.sub(r"\s+", " ", f).strip() for f in forms if f.strip()}

    return forms


def extract_ground_truth_types(binary_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Extract ground truth variable types from DWARF debug info.

    Args:
        binary_path: Path to ELF binary compiled with -g

    Returns:
        Dict mapping function_name -> list of variable dicts with:
            - name: variable name
            - type: list of normalized type strings
            - rbp_offset: list of stack offsets
            - size: byte size
    """
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.dwarf_expr import DWARFExprParser

    result: dict[str, list[dict[str, Any]]] = {}

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)

            if not elf.has_dwarf_info():
                logger.debug("No DWARF info in %s", binary_path)
                return result

            dwarfinfo = elf.get_dwarf_info()

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

    for child in die.iter_children():
        if child.tag in ("DW_TAG_lexical_block", "DW_TAG_inlined_subroutine"):
            variables.extend(_parse_lexical_block(child, dwarfinfo))
        elif child.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
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


def _parse_variable_die(die: Any, dwarfinfo: Any) -> dict[str, Any] | None:
    """Parse a variable DIE to extract type info."""
    from elftools.dwarf.dwarf_expr import DWARFExprParser

    # Get stack offsets
    offsets = _get_location(die, dwarfinfo)
    if not offsets:
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

    try:
        type_names, size = _parse_type_die(die, dwarfinfo)
    except Exception:
        pass

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
    }


def _get_location(die: Any, dwarfinfo: Any) -> list[int]:
    """Extract stack offsets from DW_AT_location."""
    from elftools.dwarf.dwarf_expr import DWARFExprParser

    offsets: list[int] = []

    if "DW_AT_location" not in die.attributes:
        return offsets

    loc_attr = die.attributes["DW_AT_location"]
    expr_parser = DWARFExprParser(dwarfinfo.structs)

    try:
        if loc_attr.form == "DW_FORM_exprloc":
            ops = expr_parser.parse_expr(loc_attr.value)
            for op in ops:
                if op.op_name == "DW_OP_fbreg":
                    offsets.append(op.args[0] + 16)

        elif loc_attr.form == "DW_FORM_sec_offset":
            loclists = dwarfinfo.location_lists()
            loclist = loclists.get_location_list_at_offset(loc_attr.value, die=die)

            for entry in loclist:
                expr = getattr(entry, "loc_expr", None) or getattr(
                    entry, "location_expr", None
                )
                if expr is None:
                    continue
                ops = expr_parser.parse_expr(expr)
                if len(ops) != 1:
                    continue
                for op in ops:
                    if op.op_name == "DW_OP_fbreg":
                        offsets.append(op.args[0] + 16)
    except Exception:
        pass

    return offsets


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
            names.append(
                type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
            )
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
            names.append(
                type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
            )
        if not names:
            names = ["struct"]
        size = 0
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return names, size

    elif tag in ("DW_TAG_union_type", "DW_TAG_class_type"):
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(
                type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
            )
        if not names:
            names = ["union"]
        size = 0
        if "DW_AT_byte_size" in type_die.attributes:
            size = type_die.attributes["DW_AT_byte_size"].value
        return names, size

    elif tag == "DW_TAG_enumeration_type":
        names = []
        if "DW_AT_name" in type_die.attributes:
            names.append(
                type_die.attributes["DW_AT_name"].value.decode("utf-8", "replace")
            )
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

        variables.append({
            "name": var_name,
            "type": list(normalize_type(type_str)),
        })

    return variables


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
        **kwargs: Any,
    ) -> MetricValue:
        """Compute type match accuracy for a single function.

        Args:
            decompiled: The decompiled function
            ground_truth_vars: Ground truth variables from DWARF
        """
        if not ground_truth_vars:
            return MetricValue(
                value=0.0,
                metadata={"error": "No ground truth types available"},
            )

        # Extract types from decompiled code
        decomp_vars = extract_types_from_decompiled_code(decompiled.decompiled_code)

        if not decomp_vars:
            # No variables found in decompilation
            fn = len(ground_truth_vars)
            return MetricValue(
                value=0.0,
                metadata={
                    "tp": 0,
                    "fp": 0,
                    "fn": fn,
                    "gt_vars": len(ground_truth_vars),
                    "decomp_vars": 0,
                },
            )

        # Build sets of normalized types for decompiled code by variable name
        decomp_type_by_name: dict[str, set[str]] = {}
        for var in decomp_vars:
            name = var["name"]
            if name not in decomp_type_by_name:
                decomp_type_by_name[name] = set()
            decomp_type_by_name[name].update(var["type"])

        # Match ground truth to decompiled by variable name
        tp = 0
        fp = 0
        fn = 0

        for gt_var in ground_truth_vars:
            gt_name = gt_var["name"]
            gt_types = set(gt_var["type"])

            if gt_name in decomp_type_by_name:
                decomp_types = decomp_type_by_name[gt_name]
                if gt_types.intersection(decomp_types):
                    tp += 1
                else:
                    fp += 1
            else:
                fn += 1

        total = tp + fp + fn
        accuracy = tp / total if total > 0 else 0.0

        return MetricValue(
            value=accuracy,
            raw_value=accuracy,
            metadata={
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "gt_vars": len(ground_truth_vars),
                "decomp_vars": len(decomp_vars),
            },
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
                "No DWARF ground truth types for %s. "
                "Binary may not have been compiled with -g.",
                binary_path,
            )

        for func_name, func_decomp in decompilation.functions.items():
            try:
                gt_vars = gt_types.get(func_name, [])
                if not gt_vars:
                    continue

                value = self.compute_for_function(
                    func_decomp,
                    ground_truth_vars=gt_vars,
                )
                function_results[func_name] = value

            except Exception as e:
                errors.append(f"{func_name}: {str(e)}")

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
