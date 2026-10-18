"""C declaration discovery and occurrence lines for local-variable correspondence."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

_C_LANGUAGE = Language(tree_sitter_c.language())
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())


@dataclass(frozen=True)
class DiscoveredVariable:
    """One declaration recovered from decompiled C without backend metadata."""

    name: str
    kind: str
    arg_index: int | None


def _parser() -> Parser:
    return Parser(_C_LANGUAGE)


def _parse_source(source: bytes):
    """Retain C behavior; use C++ when its declarators require that grammar."""
    c_tree = _parser().parse(source)
    cpp_tree = Parser(_CPP_LANGUAGE).parse(source)
    if c_tree.root_node.has_error and not cpp_tree.root_node.has_error:
        return cpp_tree
    if any(
        node.type in {"namespace_definition", "class_specifier", "template_declaration"}
        and not node.has_error
        for node in _walk(cpp_tree.root_node)
    ):
        return cpp_tree
    if not c_tree.root_node.has_error:
        return c_tree
    cpp_declarators = {"qualified_identifier", "operator_name", "destructor_name"}
    for function in _walk(cpp_tree.root_node):
        if function.type != "function_definition":
            continue
        declarator = function.child_by_field_name("declarator")
        if declarator is not None and any(
            node.type in cpp_declarators for node in _walk(declarator)
        ):
            return cpp_tree
    return c_tree


def _walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _field_name(node: Node) -> str | None:
    parent = node.parent
    if parent is None:
        return None
    for index, child in enumerate(parent.children):
        if child == node:
            return parent.field_name_for_child(index)
    return None


def _declarator_identifier(node: Node | None) -> Node | None:
    if node is None:
        return None
    if node.type in {
        "identifier",
        "field_identifier",
        "qualified_identifier",
        "operator_name",
        "destructor_name",
    }:
        return node
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        identifier = _declarator_identifier(declarator)
        if identifier is not None:
            return identifier
    for child in node.named_children:
        identifier = _declarator_identifier(child)
        if identifier is not None:
            return identifier
    return None


def _function_name(node: Node, source: bytes) -> str:
    identifier = _declarator_identifier(node.child_by_field_name("declarator"))
    name = _text(identifier, source) if identifier is not None else ""
    if not name or name.startswith("::"):
        return name
    scopes = []
    parent = node.parent
    while parent is not None:
        if parent.type in {"namespace_definition", "class_specifier", "struct_specifier"}:
            scope = parent.child_by_field_name("name")
            if scope is not None:
                scopes.append(_text(scope, source))
        parent = parent.parent
    prefix = "::".join(reversed(scopes))
    if prefix and not name.startswith(prefix + "::"):
        return prefix + "::" + name
    return name


def function_parameters(code: str, function_name: str) -> str | None:
    """Read the real argument list, including operator() and cv/noexcept suffixes."""
    source = code.encode("utf-8", "replace")
    tree = _parse_source(source)
    candidates = [
        node
        for node in _walk(tree.root_node)
        if node.type == "function_definition"
        and (
            _function_name(node, source) == function_name
            or _function_leaf(node, source) == function_name
        )
    ]
    if len(candidates) != 1:
        return None
    declarator = candidates[0].child_by_field_name("declarator")
    for node in _walk(declarator) if declarator is not None else ():
        if node.type == "parameter_list":
            text = _text(node, source)
            return text[1:-1]
    return None


def _function_leaf(node: Node, source: bytes) -> str:
    identifier = _declarator_identifier(node.child_by_field_name("declarator"))
    while identifier is not None and identifier.type == "qualified_identifier":
        identifier = identifier.child_by_field_name("name")
    return _text(identifier, source) if identifier is not None else ""


def index_c_functions(code: str) -> dict[str, tuple[str, ...]]:
    """Index every named function definition in a translation unit."""

    source = code.encode("utf-8", "replace")
    tree = _parse_source(source)
    definitions: dict[str, list[str]] = defaultdict(list)
    aliases: dict[str, set[str]] = defaultdict(set)
    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        name = _function_name(node, source)
        if name:
            definitions[name].append(_text(node, source))
            aliases[_function_leaf(node, source)].add(name)
    for leaf, names in aliases.items():
        if leaf and leaf not in definitions and len(names) == 1:
            definitions[leaf] = list(definitions[next(iter(names))])
    return {name: tuple(rows) for name, rows in definitions.items()}


def function_definition_at_line(code: str, function_name: str, line: int) -> str | None:
    """Select one parsed definition containing a proven original-source line."""
    if line < 1:
        return None
    source = code.encode("utf-8", "replace")
    tree = _parse_source(source)
    definitions = [node for node in _walk(tree.root_node) if node.type == "function_definition"]
    exact = [node for node in definitions if _function_name(node, source) == function_name]
    candidates = exact or [
        node for node in definitions if _function_leaf(node, source) == function_name
    ]
    containing = [
        node for node in candidates if node.start_point.row < line <= node.end_point.row + 1
    ]
    return _text(containing[0], source) if len(containing) == 1 else None


def _select_function(root: Node, source: bytes, function_name: str) -> Node | None:
    definitions = [node for node in _walk(root) if node.type == "function_definition"]
    exact = [node for node in definitions if _function_name(node, source) == function_name]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None
    leaves = [node for node in definitions if _function_leaf(node, source) == function_name]
    if len(leaves) == 1:
        return leaves[0]
    if len(leaves) > 1:
        return None
    return definitions[0] if len(definitions) == 1 else None


def _declaration_identifiers(node: Node) -> list[Node]:
    identifiers: list[Node] = []
    for index, child in enumerate(node.children):
        if node.field_name_for_child(index) != "declarator":
            continue
        identifier = _declarator_identifier(child)
        if identifier is not None:
            identifiers.append(identifier)
    return identifiers


def _is_function_prototype(identifier: Node) -> bool:
    node = identifier.parent
    saw_pointer = False
    while node is not None and node.type not in {"declaration", "parameter_declaration"}:
        saw_pointer |= node.type in {"pointer_declarator", "abstract_pointer_declarator"}
        if node.type == "function_declarator" and not saw_pointer:
            return True
        node = node.parent
    return False


def _storage_classes(node: Node, source: bytes) -> set[str]:
    return {
        _text(child, source).strip()
        for child in node.named_children
        if child.type == "storage_class_specifier"
    }


def _discover_variables(
    function: Node,
    source: bytes,
) -> tuple[list[DiscoveredVariable], set[Node], dict[str, list[tuple[int, int]]]]:
    declarations: list[DiscoveredVariable] = []
    declaration_nodes: set[Node] = set()
    binding_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
    body = function.child_by_field_name("body")
    declarator = function.child_by_field_name("declarator")
    parameter_list = None
    for node in _walk(declarator) if declarator is not None else ():
        if node.type == "parameter_list":
            parameter_list = node
            break
    if parameter_list is not None:
        position = 0
        for parameter in parameter_list.named_children:
            if parameter.type not in {"parameter_declaration", "optional_parameter_declaration"}:
                continue
            identifier = _declarator_identifier(parameter.child_by_field_name("declarator"))
            if identifier is None:
                position += 1
                continue
            name = _text(identifier, source)
            declarations.append(DiscoveredVariable(name, "arg", position))
            declaration_nodes.add(identifier)
            if body is not None:
                binding_ranges[name].append((body.start_byte, body.end_byte))
            position += 1

    if body is None:
        return declarations, declaration_nodes, binding_ranges
    for node in _walk(body):
        if node.type != "declaration":
            continue
        if _storage_classes(node, source) & {"typedef", "extern"}:
            continue
        for identifier in _declaration_identifiers(node):
            if _is_function_prototype(identifier):
                continue
            name = _text(identifier, source)
            declarations.append(DiscoveredVariable(name, "local", None))
            declaration_nodes.add(identifier)
            scope = identifier.parent
            while scope is not None and scope != body:
                if scope.type in {"compound_statement", "for_statement"}:
                    break
                scope = scope.parent
            if scope is None:
                scope = body
            binding_ranges[name].append((identifier.start_byte, scope.end_byte))
    return declarations, declaration_nodes, binding_ranges


def variable_occurrence_lines(
    code: str,
    function_name: str,
    variable_names: Iterable[str],
    *,
    require_exact_function_name: bool = False,
) -> dict[str, tuple[int, ...]]:
    """Locate unambiguous local-variable identifiers in exact rendered C."""

    source = code.encode("utf-8", "replace")
    tree = _parse_source(source)
    if require_exact_function_name:
        exact = [
            node
            for node in _walk(tree.root_node)
            if node.type == "function_definition"
            and (
                _function_name(node, source) == function_name
                or _function_leaf(node, source) == function_name
            )
        ]
        function = exact[0] if len(exact) == 1 else None
    else:
        function = _select_function(tree.root_node, source, function_name)
    if function is None or function.has_error:
        return {}

    discovered, declaration_nodes, binding_ranges = _discover_variables(function, source)
    requested = list(variable_names)
    requested_counts = Counter(requested)
    discovered_counts = Counter(variable.name for variable in discovered)
    target_names = {
        name
        for name, count in requested_counts.items()
        if name and count == 1 and discovered_counts.get(name) == 1
    }
    if not target_names:
        return {}

    line_starts = [0]
    line_starts.extend(index + 1 for index, byte in enumerate(source) if byte == ord("\n"))
    occurrences: dict[str, set[int]] = defaultdict(set)
    for node in _walk(function):
        if node.type != "identifier":
            continue
        name = _text(node, source)
        if name not in target_names:
            continue
        if node not in declaration_nodes:
            ranges = binding_ranges.get(name)
            if ranges and not any(start <= node.start_byte < end for start, end in ranges):
                continue
        if _field_name(node) in {"field", "label"}:
            continue
        occurrences[name].add(bisect_right(line_starts, node.start_byte))

    return {name: tuple(sorted(lines)) for name, lines in sorted(occurrences.items())}


@dataclass(frozen=True)
class FunctionDefinition:
    """One syntactic definition; display-name collisions retain separate rows."""

    name: str
    leaf: str
    code: str
    start_line: int
    end_line: int
    has_error: bool
    is_template: bool


def function_definitions(code: str) -> tuple[FunctionDefinition, ...]:
    """Retain source spans for exact native-origin joins, without name reduction."""
    source = code.encode("utf-8", "replace")
    parser = Parser(_CPP_LANGUAGE)
    tree = parser.parse(source)
    line_breaks = [index for index, byte in enumerate(source) if byte == 10]
    definitions = []
    for node in _definition_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        parent = node.parent
        template = False
        scope_error = False
        while parent is not None:
            template |= parent.type == "template_declaration"
            if parent.type in {"namespace_definition", "class_specifier", "struct_specifier"}:
                name = parent.child_by_field_name("name")
                body = parent.child_by_field_name("body")
                scope_error |= name is not None and name.has_error
                end = (
                    body.child(body.child_count - 1)
                    if body is not None and body.child_count
                    else None
                )
                scope_error |= end is None
                if end is not None:
                    scope_error |= end.type != "}" or end.is_missing
            parent = parent.parent
        definitions.append(
            FunctionDefinition(
                _function_name(node, source),
                _function_leaf(node, source),
                _text(node, source),
                bisect_right(line_breaks, node.start_byte) + 1,
                bisect_right(line_breaks, max(node.start_byte, node.end_byte - 1)) + 1,
                node.has_error or scope_error,
                template,
            )
        )
    return tuple(definitions)


def _definition_nodes(root: Node) -> Iterator[Node]:
    cursor = root.walk()
    while True:
        node = cursor.node
        is_definition = node.type == "function_definition"
        if is_definition:
            yield node
        if not is_definition and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return
