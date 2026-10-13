"""Complete ordinary C record definitions in emitted code, without oracle hints.

Natural layout is admitted only for explicit LP64/LLP64 data models. Classes,
inheritance, bitfields, packing, attributes and uncertain declarators require
an explicit producer type graph rather than a guessed layout.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

import tree_sitter_cpp
from tree_sitter import Language, Parser

from decbench.metrics.cpp_type_graph import TypeEdge, TypeGraph, TypeNode, _Builder
from decbench.metrics.cpp_types import CppType, UnsupportedType, parse_type


class RecoveredTypeContext:
    def __init__(self, code: str, data_model: str):
        self.data_model = data_model
        self.data = code.encode()
        self.builder = _Builder()
        self.definitions: dict[str, Any] = {}
        self.ambiguous: set[str] = set()
        self.alignments: dict[str, int] = {}
        self.invalid_layout = bool(
            re.search(r"#\s*pragma\s+pack|__attribute__|__declspec|alignas", code)
        )
        parser = Parser(Language(tree_sitter_cpp.language()))
        self.tree = parser.parse(self.data)
        self._index(self.tree.root_node)

    def _text(self, node: Any) -> str:
        return self.data[node.start_byte : node.end_byte].decode()

    def _index(self, node: Any, scope: str = "") -> None:
        if node.type == "namespace_definition":
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name is not None and body is not None:
                self._index(body, scope + self._text(name) + "::")
            return
        if node.type in {"struct_specifier", "union_specifier"}:
            body = node.child_by_field_name("body")
            name = node.child_by_field_name("name")
            alias = None
            if node.parent.type == "type_definition":
                alias = node.parent.child_by_field_name("declarator")
            spelling = self._text(name) if name else self._text(alias) if alias else ""
            if body is not None and spelling:
                key = scope + spelling
                if key in self.definitions:
                    self.ambiguous.add(key)
                self.definitions[key] = node
                if alias is not None and self._text(alias) != spelling:
                    alias_key = scope + self._text(alias)
                    if alias_key in self.definitions:
                        self.ambiguous.add(alias_key)
                    self.definitions[alias_key] = node
            return
        if node.type in {"translation_unit", "declaration_list", "type_definition", "declaration"}:
            for child in node.named_children:
                self._index(child, scope)

    def graph(self, spelling: str) -> TypeGraph:
        self.builder = _Builder()
        self.alignments = {}
        root = self._type(spelling)
        return self.builder.finish(root)

    def _type(self, spelling: str) -> str:
        try:
            ty = parse_type(spelling, self.data_model)
            key = "text:" + spelling
            self.builder.primitive(ty, key)
            self.alignments[key] = self._primitive_alignment(ty)
            return key
        except UnsupportedType:
            pass
        match = re.fullmatch(
            r"(const |volatile )?(?:(?:struct|union) )?([\w:]+)\s*([*&]*)", spelling.strip()
        )
        if match is None:
            raise UnsupportedType("unsupported recovered object spelling")
        qualifier, name, suffix = match.groups()
        base = "record:" + name
        if self.builder.reserve(base):
            self._record(base, name)
        if qualifier:
            qkey = base + ":" + qualifier
            if self.builder.reserve(qkey):
                self.builder.nodes[qkey] = replace(
                    self.builder.nodes[base], qualifiers=(qualifier.strip(),)
                )
                self.alignments[qkey] = self.alignments[base]
            base = qkey
        for i, char in enumerate(suffix):
            key = spelling + f"/indirection{i}"
            size = 4 if self.data_model == "ILP32" else 8
            if self.builder.reserve(key):
                self.builder.nodes[key] = TypeNode(
                    "pointer" if char == "*" else "lref", size, edges=(TypeEdge("element", base),)
                )
                self.alignments[key] = size
            base = key
        return base

    def _primitive_alignment(self, ty: CppType) -> int:
        if ty.kind == "array":
            if ty.element is None:
                raise UnsupportedType("missing array element")
            return self._primitive_alignment(ty.element)
        if self.data_model == "ILP32" and ty.byte_size() > 4:
            raise UnsupportedType("ILP32 natural alignment needs explicit target ABI")
        if not ty.byte_size():
            raise UnsupportedType("void object field")
        return ty.byte_size()

    def _declarator(self, node: Any, target: str, scope: str) -> tuple[str, str]:
        if node.type in {"field_identifier", "identifier"}:
            return self._text(node), target
        if node.type == "pointer_declarator":
            child = node.child_by_field_name("declarator")
            if child is None or any(c.type == "type_qualifier" for c in node.named_children):
                raise UnsupportedType("qualified pointer declarator requires explicit graph")
            key = scope + f"/pointer:{node.start_byte}"
            self.builder.reserve(key)
            size = 4 if self.data_model == "ILP32" else 8
            self.builder.nodes[key] = TypeNode(
                "pointer", size, edges=(TypeEdge("element", target),)
            )
            self.alignments[key] = size
            return self._declarator(child, key, scope)
        if node.type == "array_declarator":
            child = node.child_by_field_name("declarator")
            size = node.child_by_field_name("size")
            if child is None or size is None or not self._text(size).isdigit():
                raise UnsupportedType("unknown recovered array extent")
            count = int(self._text(size))
            if count < 1 or self.builder.nodes[target].kind == "pending":
                raise UnsupportedType("incomplete recovered array")
            key = scope + f"/array:{node.start_byte}"
            self.builder.reserve(key)
            self.builder.nodes[key] = TypeNode(
                "array",
                count * self.builder.nodes[target].size,
                count=count,
                edges=(TypeEdge("element", target),),
            )
            self.alignments[key] = self.alignments[target]
            return self._declarator(child, key, scope)
        raise UnsupportedType("uncertain recovered field declarator")

    def _record(self, key: str, name: str) -> None:
        node = self.definitions.get(name)
        if node is None or name in self.ambiguous or self.invalid_layout or node.has_error:
            raise UnsupportedType("complete unambiguous recovered object definition required")
        if self.data_model not in {"LP64", "LLP64"} or any(
            c.type == "base_class_clause" for c in node.named_children
        ):
            raise UnsupportedType("recovered target/object layout requires explicit graph")
        body = node.child_by_field_name("body")
        edges = []
        offset, alignment = 0, 1
        union = node.type == "union_specifier"
        for child in body.named_children:
            if child.type != "field_declaration":
                raise UnsupportedType("non-data recovered record member")
            ty_node = child.child_by_field_name("type")
            declarators = child.children_by_field_name("declarator")
            if ty_node is None or len(declarators) != 1:
                raise UnsupportedType("ambiguous recovered field declaration")
            allowed = {
                "primitive_type",
                "type_identifier",
                "qualified_identifier",
                "sized_type_specifier",
            }
            if ty_node.type not in allowed or any(
                c.type not in allowed | {"type_qualifier", declarators[0].type}
                for c in child.named_children
            ):
                raise UnsupportedType("unsupported recovered field declaration")
            spelling = " ".join(
                self._text(c)
                for c in child.named_children
                if c == ty_node or c.type == "type_qualifier"
            )
            if "::" in name and ty_node.type == "type_identifier":
                candidate = name.rsplit("::", 1)[0] + "::" + spelling
                if candidate in self.definitions:
                    spelling = candidate
            target = self._type(spelling)
            field_name, target = self._declarator(declarators[0], target, key)
            if self.builder.nodes[target].kind == "pending":
                raise UnsupportedType("recursive by-value field")
            align = self.alignments[target]
            alignment = max(alignment, align)
            position = 0 if union else (offset + align - 1) // align * align
            edges.append(TypeEdge("field", target, field_name, position * 8, access=3))
            offset = max(offset, position + self.builder.nodes[target].size)
        if not edges:
            raise UnsupportedType("empty recovered record ABI requires explicit graph")
        size = (offset + alignment - 1) // alignment * alignment
        self.builder.nodes[key] = TypeNode(
            "union" if union else "record", size, name, edges=tuple(edges)
        )
        self.alignments[key] = alignment
