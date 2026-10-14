"""Bounded source/ABI object graphs; opaque names never establish layout equality.

Graph edges retain actual debug offsets and virtual-base locators. Producers may
supply the same versioned graph contract under metadata.type_graphs (by complete
type spelling). Node identifiers are local references, never comparison evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from decbench.metrics.cpp_types import CppType, UnsupportedType, parse_type
from decbench.utils import binfmt
from decbench.utils.pdb_info import _numeric, _string, _unpack

MAX_NODES = 256


@dataclass(frozen=True)
class TypeEdge:
    role: str
    target: str
    name: str = ""
    offset_bits: int | None = None
    bit_width: int | None = None
    virtual: bool = False
    locator: str = ""
    access: int = 0
    locator_type: str | None = None


@dataclass(frozen=True)
class TypeNode:
    kind: str
    size: int
    name: str = ""
    qualifiers: tuple[str, ...] = ()
    rank: str = ""
    count: int = 0
    edges: tuple[TypeEdge, ...] = ()
    enumerators: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, eq=False)
class TypeGraph:
    root: str
    nodes: dict[str, TypeNode]
    view: str = "source"

    def byte_size(self) -> int:
        return self.nodes[self.root].size

    def project(self, view: str) -> TypeGraph:
        if view not in {"source", "abi"}:
            raise ValueError("invalid type view")
        return replace(self, view=view)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeGraph) or self.view != other.view:
            return False
        visited: set[tuple[str, str]] = set()

        def compare(a: str, b: str) -> bool:
            source = self.view == "source"
            while not source and self.nodes[a].kind == "enum":
                a = self.nodes[a].edges[0].target
            while not source and other.nodes[b].kind == "enum":
                b = other.nodes[b].edges[0].target
            if (a, b) in visited:
                return True
            visited.add((a, b))
            left, right = self.nodes[a], other.nodes[b]

            def label(n: TypeNode) -> tuple:
                kind = "pointer" if not source and n.kind in {"lref", "rref"} else n.kind
                return (
                    kind,
                    n.size,
                    n.name if source else "",
                    n.qualifiers if source else (),
                    n.rank if source else "",
                    n.count,
                    tuple(sorted(n.enumerators)) if source else (),
                )

            def edge_label(e: TypeEdge) -> tuple:
                return (
                    e.role,
                    e.name if source else "",
                    e.offset_bits,
                    e.bit_width,
                    e.virtual,
                    e.locator,
                    e.access if source else 0,
                )

            if label(left) != label(right) or len(left.edges) != len(right.edges):
                return False
            remaining = list(right.edges)
            for edge in left.edges:
                for i, candidate in enumerate(remaining):
                    if edge_label(edge) != edge_label(candidate):
                        continue
                    saved = visited.copy()
                    locator_equal = (
                        edge.locator_type is None and candidate.locator_type is None
                    ) or (
                        edge.locator_type is not None
                        and candidate.locator_type is not None
                        and compare(edge.locator_type, candidate.locator_type)
                    )
                    if locator_equal and compare(edge.target, candidate.target):
                        remaining.pop(i)
                        break
                    visited.clear()
                    visited.update(saved)
                else:
                    return False
            return True

        return compare(self.root, other.root)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TypeGraph:
        """Validate explicit producer graphs, including reachable layout completeness."""
        if not isinstance(payload, dict) or payload.get("schema") != "decbench-cpp-type-graph-v1":
            raise UnsupportedType("unknown recovered type graph schema")
        raw = payload.get("nodes")
        if not isinstance(raw, dict) or not 0 < len(raw) <= MAX_NODES:
            raise UnsupportedType("invalid recovered type graph population")
        nodes = {}
        allowed = {
            "record",
            "union",
            "enum",
            "pointer",
            "lref",
            "rref",
            "array",
            "void",
            "signed",
            "unsigned",
            "char",
            "bool",
            "float",
            "char8_t",
            "char16_t",
            "char32_t",
        }
        try:
            for key, node in raw.items():
                if (
                    not isinstance(key, str)
                    or not isinstance(node, dict)
                    or node.get("complete") is not True
                ):
                    raise UnsupportedType("incomplete recovered type node")
                value = TypeNode(
                    kind=node["kind"],
                    size=node["size"],
                    name=node.get("name", ""),
                    qualifiers=tuple(sorted(node.get("qualifiers", []))),
                    rank=node.get("rank", ""),
                    count=node.get("count", 0),
                    edges=tuple(TypeEdge(**e) for e in node.get("edges", [])),
                    enumerators=tuple(tuple(e) for e in node.get("enumerators", [])),
                )
                if value.kind not in allowed or type(value.size) is not int or value.size < 0:
                    raise UnsupportedType("invalid recovered type node")
                nodes[key] = value
            graph = cls(payload["root"], nodes)
            graph.validate()
            return graph
        except (KeyError, TypeError) as exc:
            raise UnsupportedType("invalid recovered graph contract") from exc

    def validate(self) -> None:
        if self.root not in self.nodes:
            raise UnsupportedType("missing type graph root")
        for node in self.nodes.values():
            if len(node.edges) > MAX_NODES:
                raise UnsupportedType("too many type graph edges")
            if node.kind == "enum" and (
                len(node.edges) != 1
                or self.nodes.get(node.edges[0].target, TypeNode("missing", 0)).kind
                not in {"signed", "unsigned", "char"}
            ):
                raise UnsupportedType("invalid enum underlying type")
            if node.kind == "pending":
                raise UnsupportedType("unresolved recursive type node")
            roles = [e.role for e in node.edges]
            if node.kind in {"pointer", "lref", "rref", "array", "enum"} and roles != ["element"]:
                raise UnsupportedType("missing/ambiguous element type")
            if node.kind == "array" and node.count < 1:
                raise UnsupportedType("unknown array extent")
            if (
                node.kind not in {"record", "union", "pointer", "lref", "rref", "array", "enum"}
                and roles
            ):
                raise UnsupportedType("scalar carries layout edges")
            if (
                not isinstance(node.name, str)
                or not isinstance(node.rank, str)
                or any(q not in {"const", "volatile"} for q in node.qualifiers)
            ):
                raise UnsupportedType("invalid node identity/qualifiers")
            if (
                node.kind == "array"
                and node.size != node.count * self.nodes[node.edges[0].target].size
            ):
                raise UnsupportedType("array extent disagrees with element")
            for edge in node.edges:
                if (
                    not isinstance(edge.name, str)
                    or not isinstance(edge.locator, str)
                    or type(edge.virtual) is not bool
                    or edge.access not in {0, 1, 2, 3}
                ):
                    raise UnsupportedType("invalid edge attributes")
                if edge.target not in self.nodes or edge.role not in {
                    "field",
                    "base",
                    "element",
                    "vptr",
                }:
                    raise UnsupportedType("invalid type graph edge")
                if edge.role in {"field", "base"} and not edge.virtual:
                    if type(edge.offset_bits) is not int or edge.offset_bits < 0:
                        raise UnsupportedType("unknown member offset")
                    width = (
                        edge.bit_width
                        if edge.bit_width is not None
                        else self.nodes[edge.target].size * 8
                    )
                    if (
                        type(width) is not int
                        or width < 0
                        or edge.offset_bits + width > node.size * 8
                    ):
                        raise UnsupportedType("member exceeds object extent")
                if edge.virtual and (
                    edge.role != "base" or not edge.locator or edge.offset_bits is not None
                ):
                    raise UnsupportedType("incomplete virtual base locator")
                if edge.locator_type is not None and (
                    not edge.virtual
                    or edge.locator_type not in self.nodes
                    or self.nodes[edge.locator_type].kind != "pointer"
                ):
                    raise UnsupportedType("invalid virtual base locator type")
                if edge.bit_width is not None and (
                    edge.role != "field"
                    or type(edge.bit_width) is not int
                    or not 0 < edge.bit_width <= self.nodes[edge.target].size * 8
                ):
                    raise UnsupportedType("invalid bit field storage width")
        complete: set[str] = set()
        active: set[str] = set()

        def storage_cycle(key: str) -> None:
            if key in active:
                raise UnsupportedType("cyclic by-value object storage")
            if key in complete:
                return
            active.add(key)
            node = self.nodes[key]
            if node.kind not in {"pointer", "lref", "rref"}:
                for edge in node.edges:
                    storage_cycle(edge.target)
            active.remove(key)
            complete.add(key)

        for key in self.nodes:
            storage_cycle(key)


@dataclass
class _Builder:
    nodes: dict[str, TypeNode] = field(default_factory=dict)

    def reserve(self, key: str) -> bool:
        if key in self.nodes:
            return False
        if len(self.nodes) >= MAX_NODES:
            raise UnsupportedType("type graph exceeds node bound")
        self.nodes[key] = TypeNode("pending", 0)
        return True

    def primitive(self, ty: CppType, key: str = "scalar") -> str:
        if self.reserve(key):
            edges = (
                (TypeEdge("element", self.primitive(ty.element, key + "/element")),)
                if ty.element
                else ()
            )
            self.nodes[key] = TypeNode(
                ty.kind,
                ty.byte_size(),
                qualifiers=ty.qualifiers,
                rank=ty.rank,
                count=ty.count,
                edges=edges,
            )
        return key

    def qualified(self, key: str, target: str, qualifiers: tuple[str, ...]) -> None:
        node = self.nodes[target]
        if node.kind in {"pending", "alias", "cv"}:
            self.nodes[key] = TypeNode(
                "cv", 0, qualifiers=qualifiers, edges=(TypeEdge("element", target),)
            )
        elif node.kind == "array":
            child = key + "/qualified_element"
            self.reserve(child)
            self.qualified(child, node.edges[0].target, qualifiers)
            self.nodes[key] = replace(node, edges=(TypeEdge("element", child),))
        elif node.kind in {"lref", "rref"}:
            raise UnsupportedType("cv-qualified reference graph")
        else:
            self.nodes[key] = replace(
                node, qualifiers=tuple(sorted(set(node.qualifiers) | set(qualifiers)))
            )

    def finish(self, root: str) -> TypeGraph:
        for _ in range(MAX_NODES):
            unresolved = [
                (key, node) for key, node in self.nodes.items() if node.kind in {"alias", "cv"}
            ]
            if not unresolved:
                break
            progress = False
            for key, node in unresolved:
                target = node.edges[0].target
                if self.nodes[target].kind in {"pending", "alias", "cv"}:
                    continue
                if node.kind == "cv":
                    self.qualified(key, target, node.qualifiers)
                else:
                    self.nodes[key] = self.nodes[target]
                progress = True
            if not progress:
                raise UnsupportedType("unresolved recursive type modifiers")
        result = TypeGraph(root, self.nodes)
        result.validate()
        return result


def primitive_graph(ty: CppType) -> TypeGraph:
    builder = _Builder()
    return builder.finish(builder.primitive(ty))


def _qualified_name(die: Any) -> str:
    names = []
    while die is not None:
        if die.tag in {
            "DW_TAG_namespace",
            "DW_TAG_class_type",
            "DW_TAG_structure_type",
            "DW_TAG_union_type",
            "DW_TAG_enumeration_type",
        }:
            name = binfmt.die_str_attr(die, "DW_AT_name")
            if not name:
                raise UnsupportedType("anonymous object identity unsupported")
            names.append(name)
        die = die.get_parent()
    return "::".join(reversed(names))


def dwarf_graph(variable: Any, data_model: str) -> TypeGraph:
    """Resolve complete DWARF graphs by DIE references; never borrow a named definition."""
    builder = _Builder()

    def reference(die: Any) -> str:
        attr, owner = binfmt.die_attr_owner(die, "DW_AT_type", follow_abstract_origin=True)
        return (
            visit(owner.get_DIE_from_attribute("DW_AT_type"))
            if attr
            else builder.primitive(parse_type("void", data_model))
        )

    def visit(die: Any) -> str:
        key = f"die:{die.offset}"
        if not builder.reserve(key):
            return key
        tag = die.tag

        def attr(name: str) -> Any:
            value = binfmt.die_attr(die, name)
            return value.value if value is not None else None

        if tag == "DW_TAG_typedef":
            target = reference(die)
            builder.nodes[key] = (
                builder.nodes[target]
                if builder.nodes[target].kind not in {"pending", "alias", "cv"}
                else TypeNode("alias", 0, edges=(TypeEdge("element", target),))
            )
        elif tag == "DW_TAG_base_type":
            ty = parse_type(binfmt.die_str_attr(die, "DW_AT_name") or "", data_model)
            if attr("DW_AT_byte_size") != ty.byte_size():
                raise UnsupportedType("DWARF base width disagrees with data model")
            builder.nodes[key] = TypeNode(ty.kind, ty.byte_size(), rank=ty.rank)
        elif tag in {"DW_TAG_const_type", "DW_TAG_volatile_type"}:
            target = reference(die)
            q = "const" if tag == "DW_TAG_const_type" else "volatile"
            builder.qualified(key, target, (q,))
        elif tag in {
            "DW_TAG_pointer_type",
            "DW_TAG_reference_type",
            "DW_TAG_rvalue_reference_type",
        }:
            size = attr("DW_AT_byte_size") or die.cu["address_size"]
            if size != (4 if data_model == "ILP32" else 8):
                raise UnsupportedType("DWARF pointer width disagrees with data model")
            builder.nodes[key] = TypeNode(
                {
                    "DW_TAG_pointer_type": "pointer",
                    "DW_TAG_reference_type": "lref",
                    "DW_TAG_rvalue_reference_type": "rref",
                }[tag],
                size,
                edges=(TypeEdge("element", reference(die)),),
            )
        elif tag in {"DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"}:
            size = attr("DW_AT_byte_size")
            if size is None or attr("DW_AT_declaration"):
                raise UnsupportedType("incomplete DWARF object definition")
            edges = []
            for child in die.iter_children():
                if child.tag not in {"DW_TAG_member", "DW_TAG_inheritance"}:
                    continue
                location = binfmt.die_attr(child, "DW_AT_data_member_location")
                bit_width = binfmt.die_attr(child, "DW_AT_bit_size")
                bit_offset = binfmt.die_attr(child, "DW_AT_data_bit_offset")
                virtual_attr = binfmt.die_attr(child, "DW_AT_virtuality")
                virtual = bool(virtual_attr and virtual_attr.value)
                access_attr = binfmt.die_attr(child, "DW_AT_accessibility")
                # CodeView uses public=3/protected=2/private=1; DWARF reverses public/private.
                access = (
                    {1: 3, 2: 2, 3: 1}.get(access_attr.value, 0)
                    if access_attr
                    else (1 if tag == "DW_TAG_class_type" else 3)
                )
                if child.tag == "DW_TAG_member" and location is None and bit_offset is None:
                    if binfmt.die_attr(child, "DW_AT_external") or binfmt.die_attr(
                        child, "DW_AT_declaration"
                    ):
                        continue
                    if tag != "DW_TAG_union_type":
                        raise UnsupportedType("unknown DWARF field offset")
                locator = ""
                if virtual:
                    if location is None or not isinstance(location.value, (list, bytes)):
                        raise UnsupportedType("unknown DWARF virtual base locator")
                    offset = None
                    locator = "dwarf:" + bytes(location.value).hex()
                elif bit_width is not None:
                    if bit_offset is None:
                        raise UnsupportedType("legacy/endian-dependent bit field offset")
                    offset = int(bit_offset.value)
                elif location is not None:
                    if type(location.value) is not int:
                        raise UnsupportedType("computed nonvirtual member offset")
                    offset = location.value * 8
                else:
                    offset = 0
                edges.append(
                    TypeEdge(
                        "base" if child.tag == "DW_TAG_inheritance" else "field",
                        reference(child),
                        binfmt.die_str_attr(child, "DW_AT_name") or "",
                        offset,
                        int(bit_width.value) if bit_width else None,
                        virtual,
                        locator,
                        access,
                    )
                )
            builder.nodes[key] = TypeNode(
                "union" if tag == "DW_TAG_union_type" else "record",
                int(size),
                _qualified_name(die),
                edges=tuple(edges),
            )
        elif tag == "DW_TAG_array_type":
            target = reference(die)
            counts = []
            for child in die.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    count = binfmt.die_attr(child, "DW_AT_count")
                    upper = binfmt.die_attr(child, "DW_AT_upper_bound")
                    lower = binfmt.die_attr(child, "DW_AT_lower_bound")
                    n = (
                        int(count.value)
                        if count
                        else (
                            int(upper.value) - (int(lower.value) if lower else 0) + 1
                            if upper
                            else 0
                        )
                    )
                    if n < 1:
                        raise UnsupportedType("unknown DWARF array extent")
                    counts.append(n)
            if not counts or builder.nodes[target].kind == "pending":
                raise UnsupportedType("incomplete array element")
            for i, n in reversed(list(enumerate(counts))):
                node = TypeNode(
                    "array",
                    n * builder.nodes[target].size,
                    count=n,
                    edges=(TypeEdge("element", target),),
                )
                if i:
                    inner = key + f"/dim{i}"
                    builder.reserve(inner)
                    builder.nodes[inner] = node
                    target = inner
                else:
                    builder.nodes[key] = node
        elif tag == "DW_TAG_enumeration_type":
            target = reference(die)
            values = tuple(
                (
                    binfmt.die_str_attr(c, "DW_AT_name") or "",
                    int(binfmt.die_attr(c, "DW_AT_const_value").value),
                )
                for c in die.iter_children()
                if c.tag == "DW_TAG_enumerator"
            )
            if attr("DW_AT_byte_size") is None or builder.nodes[target].kind == "void":
                raise UnsupportedType("incomplete enum underlying type")
            builder.nodes[key] = TypeNode(
                "enum",
                int(attr("DW_AT_byte_size")),
                _qualified_name(die),
                edges=(TypeEdge("element", target),),
                enumerators=values,
            )
        else:
            raise UnsupportedType(f"unsupported DWARF graph {tag}")
        return key

    return builder.finish(reference(variable))


def pdb_graph(types: Any, index: int, data_model: str) -> TypeGraph:
    """Follow CodeView indices, preserving fields, ordinary bases and virtual locators."""
    builder = _Builder()

    def visit(index: int) -> str:
        key = f"cv:{index:x}"
        if not builder.reserve(key):
            return key
        if index < 0x1000:
            scalar = types.resolve(index)
            if scalar is None:
                raise UnsupportedType("unsupported CodeView primitive")
            ty = parse_type(scalar.source_name, data_model)
            if ty.byte_size() != scalar.size:
                raise UnsupportedType("CodeView primitive data model mismatch")
            builder.nodes[key] = builder.nodes[builder.primitive(ty, key + "/primitive")]
            return key
        record = types.records.get(index)
        if record is None:
            raise UnsupportedType("missing CodeView type record")
        kind, data = record
        if kind in {0x1504, 0x1505, 0x1519, 0x1506}:
            layout = types.record_layout(index)
            edges = []
            for member in layout["members"]:
                role = member["kind"]
                if role == "enumerator":
                    raise UnsupportedType("enumerator in object field list")
                target_index = member["type_index"]
                width = None
                position = member.get("offset")
                offset = position * 8 if position is not None else None
                bit_record = types.records.get(target_index)
                if bit_record and bit_record[0] == 0x1205:
                    target_index, width, bit_position = _unpack("<IBB", bit_record[1])
                    offset = offset + bit_position if offset is not None else None
                locator = member.get("locator")
                if role == "vptr":
                    raise UnsupportedType("CodeView vptr physical offset unavailable")
                edges.append(
                    TypeEdge(
                        role,
                        visit(target_index),
                        member.get("name", ""),
                        offset,
                        width,
                        member.get("virtual", False),
                        (
                            f"codeview:{locator['vbptr_offset']}:{locator['table_index']}"
                            if locator
                            else ""
                        ),
                        member.get("access", 0),
                        visit(locator["vbptr_type"]) if locator else None,
                    )
                )
            builder.nodes[key] = TypeNode(
                layout["kind"], layout["size"], layout["name"], edges=tuple(edges)
            )
        elif kind == 0x1002:
            base, attrs = _unpack("<II", data)
            mode = (attrs >> 5) & 7
            size = (attrs >> 13) & 63 or {10: 4, 12: 8}.get(attrs & 31)
            if (
                mode not in {0, 1, 4}
                or size != (4 if data_model == "ILP32" else 8)
                or attrs & 0x1000
            ):
                raise UnsupportedType("unsupported CodeView pointer/member pointer")
            qualifiers = tuple(
                q for q, flag in (("const", 0x400), ("volatile", 0x200)) if attrs & flag
            )
            builder.nodes[key] = TypeNode(
                {0: "pointer", 1: "lref", 4: "rref"}[mode],
                size,
                qualifiers=qualifiers,
                edges=(TypeEdge("element", visit(base)),),
            )
        elif kind == 0x1001:
            base, flags = _unpack("<IH", data)
            target = visit(base)
            if flags & ~3:
                raise UnsupportedType("unsupported CodeView modifier")
            q = tuple(q for q, flag in (("const", 1), ("volatile", 2)) if flags & flag)
            builder.qualified(key, target, q)
        elif kind == 0x1503:
            base = _unpack("<I", data)[0]
            size, _ = _numeric(data, 8)
            target = visit(base)
            n = builder.nodes[target]
            if not n.size or size % n.size or size <= 0:
                raise UnsupportedType("incomplete CodeView array")
            builder.nodes[key] = TypeNode(
                "array", size, count=size // n.size, edges=(TypeEdge("element", target),)
            )
        elif kind == 0x1507:
            base, fields = _unpack("<II", data, 4)
            target = visit(base)
            name, _ = _string(data, 12)
            values = types.field_records(fields)
            if any(v["kind"] != "enumerator" for v in values):
                raise UnsupportedType("invalid enum field list")
            builder.nodes[key] = TypeNode(
                "enum",
                builder.nodes[target].size,
                name,
                edges=(TypeEdge("element", target),),
                enumerators=tuple((v["name"], v["value"]) for v in values),
            )
        else:
            raise UnsupportedType(f"unsupported CodeView graph leaf 0x{kind:x}")
        return key

    return builder.finish(visit(index))


class RecoveredGraphContext(Protocol):
    def graph(self, spelling: str) -> TypeGraph: ...


def recovered_graph(
    spelling: str,
    data_model: str,
    metadata: dict[str, Any],
    context: RecoveredGraphContext | None = None,
) -> TypeGraph:
    """Require complete producer graphs for object types; scalar spelling stays supported."""
    payload = metadata.get("type_graphs", {}).get(spelling)
    if payload is not None:
        return TypeGraph.from_payload(payload)
    try:
        return primitive_graph(parse_type(spelling, data_model))
    except UnsupportedType:
        if context is None:
            raise
        return context.graph(spelling)
