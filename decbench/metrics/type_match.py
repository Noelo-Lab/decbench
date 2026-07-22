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


# --- Uncommitted (width-only) decompiler types --------------------------------
# A decompiler often recovers a variable's SIZE but not a committed C type
# (Ghidra ``undefined8``, IDA ``__int64``/``_QWORD``, kuna ``int8``). Crediting
# such an uncommitted N-byte type against a ground-truth scalar of the same width
# is fair ("it knew it was 8 bytes"); crediting it against a POINTER or an
# aggregate is NOT — recovering a ``char *`` as a bare 8-byte scalar is a real
# type miss (and ``struct *`` -> ``void *`` stays a miss too, handled by exact
# name matching, not here).
_UNCOMMITTED_TYPES = re.compile(
    r"^\s*(?:"
    r"undefined\d*"  # Ghidra: undefined, undefined1..8
    r"|__u?int(?:8|16|32|64)"  # IDA: __int64 / __uint32 / ...
    r"|_(?:BYTE|WORD|DWORD|QWORD)"  # IDA: _QWORD / _DWORD / ...
    r"|u?int[1-8]"  # kuna: int4 / uint8 (sized in BYTES)
    r"|byte|word|dword|qword"  # Ghidra: byte / word / dword / qword
    r"|uchar"
    r")\s*$"
)
# Byte width implied by an uncommitted spelling when ``VariableInfo.size`` is
# absent (angr/ghidra usually populate ``size``, so this is a fallback).
_UNCOMMITTED_WIDTH: dict[str, int] = {
    "undefined": 1,
    "undefined1": 1,
    "byte": 1,
    "uchar": 1,
    "_BYTE": 1,
    "int1": 1,
    "uint1": 1,
    "__int8": 1,
    "__uint8": 1,
    "undefined2": 2,
    "word": 2,
    "_WORD": 2,
    "int2": 2,
    "uint2": 2,
    "__int16": 2,
    "__uint16": 2,
    "undefined4": 4,
    "dword": 4,
    "_DWORD": 4,
    "int4": 4,
    "uint4": 4,
    "__int32": 4,
    "__uint32": 4,
    "undefined8": 8,
    "qword": 8,
    "_QWORD": 8,
    "int8": 8,
    "uint8": 8,
    "__int64": 8,
    "__uint64": 8,
}
# Normalized ground-truth scalar names of each byte width. An uncommitted N-byte
# decompiler var matches a GT var whose normalized type set intersects this.
# Integer + bool only (a committed ``float``/``double`` is a type the decompiler
# demonstrably failed to recover, so it stays a miss); pointers/aggregates never
# appear here, so scalar<->pointer and struct*->void* correctly stay misses.
_SIZE_SCALARS: dict[int, set[str]] = {
    1: {"char", "bool"},
    2: {"short"},
    4: {"int"},
    8: {"long long"},
}

# Ghidra/IDA encode a stack slot's frame offset in the variable NAME
# (``local_28``, ``var_28``) but sometimes leave ``stack_offset`` unset. These
# names are unambiguously frame-negative locals; the per-binary/-function
# calibration absorbs the constant base difference vs DWARF, and its "needs >=2
# aligned" guard means a wrongly-parsed offset simply fails to calibrate (no
# harm). Deliberately excludes ``*Stack_*`` names (mixed sign conventions).
_NAME_OFFSET = re.compile(r"^(?:local|var)_([0-9a-fA-F]+)$")


def _uncommitted_size(var: Any) -> int | None:
    """Byte width of an uncommitted (width-only) decompiler type, else ``None``.

    A pointer spelling (contains ``*``) is a committed type, never uncommitted.
    """
    t = (getattr(var, "type", "") or "").strip()
    if "*" in t or not _UNCOMMITTED_TYPES.match(t):
        return None
    size = getattr(var, "size", None)
    if size in _SIZE_SCALARS:
        return int(size)
    return _UNCOMMITTED_WIDTH.get(t)


def _effective_offset(var: Any) -> int | None:
    """Stack offset for a decompiled var, recovering it from ``local_``/``var_``
    names when ``stack_offset`` is unset (Ghidra register-SSA vars stay ``None``)."""
    if getattr(var, "stack_offset", None) is not None:
        return var.stack_offset
    m = _NAME_OFFSET.match(getattr(var, "name", "") or "")
    if m:
        return -int(m.group(1), 16)
    return None


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


# Match common C local-variable declarations:
#   type name;  |  type name = ...;  |  type *name;  |  type name[N];
_DECL_PATTERN = re.compile(
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

_DECL_SKIP = frozenset({"if", "else", "while", "for", "return", "switch", "case", "break"})


def _extract_local_decls(code: str) -> list[tuple[str, str]]:
    """(name, RAW type string) for each local declaration in ``code``."""
    out: list[tuple[str, str]] = []
    for match in _DECL_PATTERN.finditer(code):
        var_name = match.group(2).strip()
        if var_name in _DECL_SKIP:
            continue
        out.append((var_name, match.group(1).strip()))
    return out


def extract_types_from_decompiled_code(code: str) -> list[dict[str, Any]]:
    """Extract variable declarations and their types from decompiled C code.

    Uses regex-based parsing to find variable declarations.
    Returns list of dicts with 'name' and 'type' fields.
    """
    return [
        {"name": name, "type": list(normalize_type(type_str))}
        for name, type_str in _extract_local_decls(code)
    ]


def _split_top_level_commas(s: str) -> list[str]:
    """Split ``s`` on commas that are not nested inside (), [], or {}."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _find_definition_params(code: str, func_name: str) -> str | None:
    """Raw parameter-list text of ``func_name``'s DEFINITION, or None.

    The definition is the occurrence whose matching ``)`` is followed by ``{``
    (a call or a prototype ending in ``;`` is not). Balanced-paren scan so
    function-pointer parameters with nested parens are handled.
    """
    if not func_name:
        return None
    for m in re.finditer(r"\b" + re.escape(func_name) + r"\s*\(", code):
        open_i = code.index("(", m.start())
        depth = 0
        close_i: int | None = None
        for j in range(open_i, len(code)):
            c = code[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    close_i = j
                    break
        if close_i is None:
            continue
        if code[close_i + 1 :].lstrip().startswith("{"):
            return code[open_i + 1 : close_i]
    return None


def _parse_param(param: str) -> tuple[str, str] | None:
    """(name, RAW type) for one C parameter, or None for ``void``/unnamed."""
    p = param.strip()
    if not p or p == "void":
        return None
    # function pointer:  ret (*name)(args)  /  ret (*name[N])(args)
    m = re.search(r"\(\s*\*+\s*(\w+)\s*(?:\[[^\]]*\])?\s*\)", p)
    if m:
        return m.group(1), (p[: m.start()] + "(*)" + p[m.end() :]).strip()
    p = re.sub(r"\[[^\]]*\]\s*$", "", p).strip()  # drop a trailing array subscript
    m = re.search(r"([A-Za-z_]\w*)\s*$", p)  # the last identifier is the name
    if not m:
        return None
    name = m.group(1)
    type_ = p[: m.start()].strip()
    if not type_:  # a lone identifier is a type without a parameter name
        return None
    return name, type_


def parse_c_variables(code: str, func_name: str) -> list[Any]:
    """Best-effort structured ``VariableInfo`` list from decompiled C text.

    Recovers function ARGUMENTS (with ABI ``arg_index``, name-independent) from
    ``func_name``'s signature plus local declarations from the body, so a
    decompiler that emits only C text (the LLM backends) is scored by the same
    argument-position + name matching as one exposing structured variables —
    instead of the name-only regex fallback, which never credited arguments (a
    function whose only variables are its arguments therefore scored 0 despite
    perfect argument types, e.g. ``wcomment(FILE *fp, int c)``).
    """
    from decbench.models.decompilation import VariableInfo

    out: list[Any] = []
    params = _find_definition_params(code, func_name)
    argnames: set[str] = set()
    if params is not None:
        for i, raw in enumerate(_split_top_level_commas(params)):
            parsed = _parse_param(raw)
            if parsed is None:
                # A non-void, un-nameable slot still occupies its ABI position.
                token = raw.strip()
                if token and token != "void":
                    out.append(VariableInfo(name="", type=token, arg_index=i, kind="arg"))
                continue
            name, type_ = parsed
            argnames.add(name)
            out.append(VariableInfo(name=name, type=type_, arg_index=i, kind="arg"))
    for name, type_ in _extract_local_decls(code):
        if name in argnames:
            continue
        out.append(VariableInfo(name=name, type=type_, kind="stack"))
    return out


def _candidate_shifts(gt_offsets: list[int], decomp_offsets: list[int]) -> list[int]:
    """The additive shifts worth testing to align decompiled to GT offsets.

    A shift ``k`` can only align a slot when ``k = g - d`` for some ground-truth
    ``g`` and decompiled ``d`` (plus ``k = 0``). Enumerating exactly those
    differences is **adaptive and uncapped**: it covers any frame size instead of
    a fixed window. This matters because a decompiler's stack offsets need not be
    rbp/CFA-relative like DWARF — IDA's Hex-Rays offsets are *frame-bottom*
    relative, so they differ from DWARF by a per-function constant (≈ the frame
    size) that routinely exceeds ±32. Sorted by increasing ``|k|`` so ties resolve
    toward the smallest magnitude.
    """
    candidates = {g - d for g in gt_offsets for d in decomp_offsets}
    candidates.add(0)
    return sorted(candidates, key=lambda x: (abs(x), x))


def _calibrate_shift(gt_offsets: list[int], decomp_offsets: list[int]) -> int | None:
    """Find an additive shift aligning decompiled offsets to ground-truth offsets.

    Tests the adaptive candidate shifts (see :func:`_candidate_shifts` — no fixed
    ``±32`` window, so frame-bottom-relative conventions like IDA's are handled),
    picking the ``k`` (ties toward smallest ``|k|``) that maximizes the count of
    decompiled offsets ``d`` where ``d + k`` is a ground-truth offset. To avoid
    spurious single-variable alignments: if a nonzero ``k`` is best and there are
    at least 2 decompiled offsets, that ``k`` must align at least 2 offsets;
    otherwise fall back to ``k = 0`` if it aligns at least 1, else return ``None``.

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
    for k in _candidate_shifts(gt_offsets, decomp_offsets):
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

    # Binary-wide calibration stays in the ±32 window: pooled across the binary
    # it is robust for the decompilers whose offsets are already rbp/CFA-relative
    # (a small constant), and keeping it narrow avoids a coincidental large shift
    # winning the vote. IDA's per-function frame-bottom offsets are handled
    # separately by the per-function override in _match_structured, so they do
    # not need (and must not perturb) this binary-wide shift.
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

    # v2: per-function, adaptive (uncapped) stack-offset calibration so IDA's
    # frame-bottom-relative offsets align with DWARF (the old binary-wide ±32
    # shift silently failed for IDA, scoring most of its stack vars as misses).
    # v3: uncommitted (width-only) types match a same-width GT scalar; recover
    # local_/var_ name-encoded stack offsets; pointers/aggregates stay strict.
    # v4: code-only decompilers (LLM backends) with no structured variables now
    # get their C signature parsed into arguments (ABI position) + locals and run
    # through the structured matcher — the old name-only regex fallback never
    # credited arguments, zeroing functions whose only variables are their args.
    cache_version = "4"

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

        # Code-only decompilers (the LLM backends) expose no structured variables.
        # Parse the emitted C into arguments (with ABI position) + locals so they
        # get the same name-independent argument-position matching as everyone
        # else, instead of the name-only regex fallback that never scored args.
        if not decompiled.variables and decompiled.decompiled_code:
            parsed = parse_c_variables(decompiled.decompiled_code, decompiled.name)
            if parsed:
                decompiled = decompiled.model_copy(update={"variables": parsed})

        decomp_stack_vars = sum(1 for v in decompiled.variables if _effective_offset(v) is not None)

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
        gt_offsets: list[int] = []
        for gv in ground_truth_vars:
            gt_offsets.extend(gv.get("rbp_offset", []))
        # Effective offsets recover ``local_``/``var_`` name-encoded slots that
        # some backends leave with ``stack_offset=None`` (see _effective_offset).
        var_offsets: list[int | None] = [_effective_offset(v) for v in decompiled.variables]
        decomp_offsets = [o for o in var_offsets if o is not None]
        gt_off_set = set(gt_offsets)

        def _aligned(kk: int | None) -> int:
            if kk is None or not decomp_offsets:
                return 0
            return len({d + kk for d in decomp_offsets} & gt_off_set)

        # Start from the binary-wide calibrated shift (robust for functions with
        # few stack slots), then override with THIS function's own shift when it
        # aligns strictly more of the function's slots. IDA's Hex-Rays offsets are
        # frame-bottom relative, so the GT<->decompiler gap is a *per-function*
        # constant (≈ frame size) that no single binary-wide shift can fit;
        # per-function calibration recovers those matches. Decompilers whose
        # offsets are already binary-consistent are unaffected — their
        # per-function shift never aligns strictly more than the binary one.
        shift: int | None = calibration_shift if calibration_shift is not None else 0
        func_shift = _calibrate_shift(gt_offsets, decomp_offsets)
        if func_shift is not None and _aligned(shift) == 0 and _aligned(func_shift) > 0:
            # Pure rescue: only when the binary-wide shift aligns NONE of this
            # function's stack slots do we fall back to its own calibrated shift.
            # This is the IDA case — its Hex-Rays offsets are frame-bottom
            # relative, so the per-function GT gap is ≈ the frame size and no
            # binary-wide ±32 shift fits. Decompilers whose offsets are already
            # binary-consistent keep aligning >0 under the binary shift, so this
            # never fires for them and their scores are byte-for-byte unchanged.
            shift = func_shift

        k = shift if shift is not None else 0

        var_types: list[set[str]] = [normalize_type(v.type) for v in decompiled.variables]
        # Width of each decompiled var's uncommitted (undefinedN/__intN/...) type,
        # else None. An uncommitted N-byte var matches a GT scalar of that width.
        var_unc: list[int | None] = [_uncommitted_size(v) for v in decompiled.variables]
        by_arg_index: dict[int, int] = {}
        by_off: dict[int, list[int]] = {}
        by_name: dict[str, list[int]] = {}
        for i, v in enumerate(decompiled.variables):
            if v.arg_index is not None and v.arg_index not in by_arg_index:
                by_arg_index[v.arg_index] = i
            if var_offsets[i] is not None:
                by_off.setdefault(var_offsets[i] + k, []).append(i)
            if v.name:
                by_name.setdefault(v.name, []).append(i)

        def _matches(gt_forms: set[str], i: int) -> bool:
            """Does decompiled var ``i`` type-match a GT var with these forms?

            True on an exact normalized-name intersection OR when the decompiled
            var is an uncommitted (width-only) type and the GT var is a scalar of
            the same width. Pointers/aggregates never enter ``_SIZE_SCALARS``, so
            scalar<->pointer and struct*->void* stay misses.
            """
            if gt_forms & var_types[i]:
                return True
            sz = var_unc[i]
            return sz is not None and bool(_SIZE_SCALARS.get(sz, set()) & gt_forms)

        used: set[int] = set()

        def claim(candidates: list[int], gt_types: set[str]) -> bool | None:
            """Claim the best unused candidate: True=tp, False=fp, None=miss."""
            avail = [i for i in candidates if i not in used]
            if not avail:
                return None
            hit = next((i for i in avail if _matches(gt_types, i)), None)
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
            verdicts[gi] = _matches(set(gv.get("type", [])), di)
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
            func_dec = [
                o for o in (_effective_offset(v) for v in func_decomp.variables) if o is not None
            ]
            if func_gt and func_dec:
                pairs.append((func_gt, func_dec))

        return _calibrate_shift_multi(pairs)
