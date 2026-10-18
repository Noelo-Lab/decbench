"""Versioned, conservative C++ type descriptors. No C-era lossy normalization.

This is a proposal implementation, not the public leaderboard's type policy.
Named object layout, enums, member/function pointers and alias recovery require
additional contracts; an unsupported oracle type excludes the whole function.
An unsupported *recovered* type is a miss, never an evaluator exclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from decbench.utils import binfmt

POLICY_VERSION = "cpp-types-v2-proposal"


@dataclass(frozen=True)
class CppType:
    kind: str
    bits: int = 0
    qualifiers: tuple[str, ...] = ()
    element: CppType | None = None
    count: int = 0
    rank: str = ""

    def byte_size(self) -> int:
        if self.kind == "array":
            if self.element is None:
                raise UnsupportedType("array has no element")
            return self.count * self.element.byte_size()
        return self.bits // 8

    def project(self, view: str) -> CppType:
        if view == "source":
            return self
        if view != "abi":
            raise ValueError("view must be source or abi")
        return replace(
            self,
            kind="pointer" if self.kind in {"lref", "rref"} else self.kind,
            qualifiers=(),
            rank="",
            element=self.element.project(view) if self.element else None,
        )


class UnsupportedType(ValueError):
    """The ground truth cannot support a complete policy verdict."""


def parse_type(spelling: str, data_model: str) -> CppType:
    """Parse only the documented scalar / ordinary indirection subset.

    Never erase a namespace, instantiate a template, equate a name to an object
    layout, decay an array, or award width-only undefinedN credit.
    """
    if data_model not in {"LP64", "LLP64", "ILP32"}:
        raise ValueError("data_model must be explicitly LP64, LLP64 or ILP32")
    tokens = re.findall(r"&&|\w+|[^\s]", spelling)
    boundary = next((i for i, t in enumerate(tokens) if t in {"*", "&", "&&", "["}), len(tokens))
    base = tokens[:boundary]
    qualifiers = tuple(sorted({t for t in base if t in {"const", "volatile"}}))
    words = [t for t in base if t not in {"const", "volatile"}]
    name = " ".join(words)
    long_bits = 64 if data_model == "LP64" else 32
    pointer_bits = 32 if data_model == "ILP32" else 64
    aliases = {
        "uint": "unsigned int",
        "ushort": "unsigned short",
        "uchar": "unsigned char",
        "ulong": "unsigned long",
        "size_t": (
            "unsigned long"
            if data_model == "LP64"
            else ("unsigned long long" if data_model == "LLP64" else "unsigned int")
        ),
        "ssize_t": (
            "long" if data_model == "LP64" else ("long long" if data_model == "LLP64" else "int")
        ),
    }
    source_alias = name in {"size_t", "ssize_t"}
    name = aliases.get(name, name)
    fixed = re.fullmatch(r"(u?)int(8|16|32|64)_t", name)
    if fixed:
        # A fixed-width alias does not prove its fundamental C++ rank (long
        # and long long can both be 64 bits). It may match only in the ABI view.
        ty = CppType(
            "unsigned" if fixed[1] else "signed",
            int(fixed[2]),
            qualifiers,
            rank="fixed_width_alias",
        )
    elif name in {"void", "bool", "char", "char8_t", "char16_t", "char32_t", "float", "double"}:
        kind, bits = {
            "void": ("void", 0),
            "bool": ("bool", 8),
            "char": ("char", 8),
            "char8_t": ("char8_t", 8),
            "char16_t": ("char16_t", 16),
            "char32_t": ("char32_t", 32),
            "float": ("float", 32),
            "double": ("float", 64),
        }[name]
        ty = CppType(kind, bits, qualifiers, rank=name)
    else:
        parts = name.split()
        unsigned = "unsigned" in parts
        if "signed" in parts and unsigned:
            raise UnsupportedType(f"invalid signedness: {spelling}")
        core = [p for p in parts if p not in {"signed", "unsigned", "int"}]
        valid = {
            (): 32,
            ("char",): 8,
            ("short",): 16,
            ("long",): long_bits,
            ("long", "long"): 64,
            ("__int8",): 8,
            ("__int16",): 16,
            ("__int32",): 32,
            ("__int64",): 64,
        }
        if (
            not parts
            or tuple(core) not in valid
            or parts.count("int") > 1
            or parts.count("unsigned") > 1
            or parts.count("signed") > 1
            or ("int" in parts and core and (core[0] == "char" or core[0].startswith("__int")))
        ):
            raise UnsupportedType(f"unsupported nominal/complex type: {spelling}")
        rank = " ".join(core) or "int"
        if rank.startswith("__int"):
            rank = "fixed_width_alias"
        ty = CppType(
            "unsigned" if unsigned else "signed", valid[tuple(core)], qualifiers, rank=rank
        )
    if source_alias:
        ty = replace(ty, rank="fixed_width_alias")
    i = boundary
    array_counts: list[int] = []
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if token in {"*", "&", "&&"} and not array_counts:
            q = []
            while i < len(tokens) and tokens[i] in {"const", "volatile"}:
                q.append(tokens[i])
                i += 1
            if token != "*" and q:
                raise UnsupportedType("cv-qualified reference")
            if ty.kind in {"lref", "rref"}:
                raise UnsupportedType("invalid nested reference")
            ty = CppType(
                {"*": "pointer", "&": "lref", "&&": "rref"}[token],
                pointer_bits,
                tuple(sorted(set(q))),
                ty,
            )
        elif token == "[" and i + 1 < len(tokens) and tokens[i].isdigit() and tokens[i + 1] == "]":
            count = int(tokens[i])
            i += 2
            if count < 1:
                raise UnsupportedType("unknown/zero array extent")
            array_counts.append(count)
        else:
            raise UnsupportedType(f"unsupported declarator: {spelling}")
    for count in reversed(array_counts):
        if ty.kind in {"lref", "rref", "void"}:
            raise UnsupportedType("invalid array element category")
        ty = CppType("array", element=ty, count=count)
    return ty


def dwarf_type(variable: Any, data_model: str, depth: int = 0) -> CppType:
    """Read the actual DIE graph, retaining cv and reference categories."""
    if depth > 32:
        raise UnsupportedType("cyclic/deep DWARF type")
    attr, owner = binfmt.die_attr_owner(variable, "DW_AT_type", follow_abstract_origin=True)
    if attr is None:
        return CppType("void", rank="void")
    die = owner.get_DIE_from_attribute("DW_AT_type")
    tag = die.tag
    if tag == "DW_TAG_typedef":
        return dwarf_type(die, data_model, depth + 1)
    if tag == "DW_TAG_base_type":
        name = binfmt.die_str_attr(die, "DW_AT_name") or ""
        result = parse_type(name, data_model)
        size = binfmt.die_attr(die, "DW_AT_byte_size")
        if size is None or result.bits != int(size.value) * 8:
            raise UnsupportedType("base type width disagrees with explicit data model")
        return result
    if tag in {"DW_TAG_const_type", "DW_TAG_volatile_type"}:
        element = dwarf_type(die, data_model, depth + 1)
        qualifier = "const" if tag == "DW_TAG_const_type" else "volatile"

        def qualify(value: CppType) -> CppType:
            # cv on an array typedef qualifies its elements, at every array
            # dimension; cv on a pointer qualifies the pointer itself.
            if value.kind == "array" and value.element is not None:
                return replace(value, element=qualify(value.element))
            if value.kind in {"lref", "rref"}:
                raise UnsupportedType("cv-qualified reference oracle")
            return replace(value, qualifiers=tuple(sorted(set(value.qualifiers) | {qualifier})))

        return qualify(element)
    if tag in {"DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"}:
        size = binfmt.die_attr(die, "DW_AT_byte_size")
        bits = int(size.value) * 8 if size else int(die.cu["address_size"]) * 8
        expected = 32 if data_model == "ILP32" else 64
        if bits != expected:
            raise UnsupportedType("pointer width disagrees with data model")
        return CppType(
            {
                "DW_TAG_pointer_type": "pointer",
                "DW_TAG_reference_type": "lref",
                "DW_TAG_rvalue_reference_type": "rref",
            }[tag],
            bits,
            element=dwarf_type(die, data_model, depth + 1),
        )
    if tag == "DW_TAG_array_type":
        counts = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count = child.attributes.get("DW_AT_count")
            upper = child.attributes.get("DW_AT_upper_bound")
            lower = child.attributes.get("DW_AT_lower_bound")
            if count is not None and count.form.startswith("DW_FORM_data"):
                counts.append(int(count.value))
            elif upper is not None and upper.form.startswith("DW_FORM_data"):
                counts.append(int(upper.value) - (int(lower.value) if lower else 0) + 1)
            else:
                raise UnsupportedType("dynamic/unknown array extent")
        if not counts or any(c < 1 for c in counts):
            raise UnsupportedType("incomplete array")
        result = dwarf_type(die, data_model, depth + 1)
        for count in reversed(counts):
            result = CppType("array", element=result, count=count)
        return result
    raise UnsupportedType(f"unsupported DWARF type category: {tag}")


def dwarf_location_supported(variable: Any, dwarf: Any) -> None:
    """Reject partial/composite/computed locations rather than grade a subset."""
    from elftools.dwarf.dwarf_expr import DWARFExprParser

    attr = variable.attributes.get("DW_AT_location")
    if attr is None:
        return
    parser = DWARFExprParser(dwarf.structs)
    if attr.form == "DW_FORM_exprloc":
        expressions = [attr.value]
    elif attr.form == "DW_FORM_sec_offset":
        expressions = [
            e.loc_expr
            for e in dwarf.location_lists().get_location_list_at_offset(attr.value, die=variable)
            if getattr(e, "loc_expr", None)
        ]
    else:
        raise UnsupportedType(f"unsupported location form: {attr.form}")
    for expression in expressions:
        ops = parser.parse_expr(expression)
        if len(ops) != 1 or not re.fullmatch(
            r"DW_OP_(fbreg|reg\d+|regx|breg\d+|bregx|addr)", ops[0].op_name
        ):
            raise UnsupportedType("partial/composite/computed DWARF location")
