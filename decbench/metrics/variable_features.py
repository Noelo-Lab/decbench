"""C declaration discovery and occurrence lines for local-variable correspondence."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import tree_sitter_c
from tree_sitter import Language, Node, Parser

_C_LANGUAGE = Language(tree_sitter_c.language())


@dataclass(frozen=True)
class DiscoveredVariable:
    """One declaration recovered from decompiled C without backend metadata."""

    name: str
    kind: str
    arg_index: int | None


@dataclass(frozen=True)
class FunctionAnalysis:
    """Declaration discovery and parse diagnostics for one C function."""

    variables: tuple[DiscoveredVariable, ...]
    function_found: bool
    has_parse_error: bool
    ambiguous_names: tuple[str, ...]


def _parser() -> Parser:
    return Parser(_C_LANGUAGE)


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
    if node.type == "identifier":
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
    return _text(identifier, source) if identifier is not None else ""


def index_c_functions(code: str) -> dict[str, tuple[str, ...]]:
    """Index every named function definition in a translation unit."""

    source = code.encode("utf-8", "replace")
    tree = _parser().parse(source)
    definitions: dict[str, list[str]] = defaultdict(list)
    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        name = _function_name(node, source)
        if name:
            definitions[name].append(_text(node, source))
    return {name: tuple(rows) for name, rows in definitions.items()}


def extract_c_function(code: str, function_name: str) -> str | None:
    """Return an exact named definition, or the sole definition as a fallback."""

    definitions = index_c_functions(code)
    exact = definitions.get(function_name, ())
    if len(exact) == 1:
        return exact[0]
    all_definitions = [definition for rows in definitions.values() for definition in rows]
    return all_definitions[0] if len(all_definitions) == 1 else None


def _select_function(root: Node, source: bytes, function_name: str) -> Node | None:
    definitions = [node for node in _walk(root) if node.type == "function_definition"]
    exact = [node for node in definitions if _function_name(node, source) == function_name]
    if len(exact) == 1:
        return exact[0]
    return definitions[0] if len(definitions) == 1 else None


def _wrapped_fragment(code: str) -> str:
    start = code.find("{")
    end = code.rfind("}")
    body = code[start + 1 : end] if 0 <= start < end else code
    return f"void __decbench_fragment(void) {{\n{body}\n}}"


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


def analyze_c_function(
    code: str,
    function_name: str,
    variable_names: Iterable[str] | None = None,
) -> FunctionAnalysis:
    """Discover local declarations in one C function and flag shadowed names."""

    source = code.encode("utf-8", "replace")
    tree = _parser().parse(source)
    function = _select_function(tree.root_node, source, function_name)
    exact_function_found = function is not None
    if function is None:
        definitions = [node for node in _walk(tree.root_node) if node.type == "function_definition"]
        if definitions:
            return FunctionAnalysis((), False, tree.root_node.has_error, ())
        source = _wrapped_fragment(code).encode("utf-8", "replace")
        tree = _parser().parse(source)
        function = _select_function(tree.root_node, source, "__decbench_fragment")
        if function is None:
            return FunctionAnalysis((), False, tree.root_node.has_error, ())

    discovered, _declaration_nodes, _binding_ranges = _discover_variables(function, source)
    requested = (
        list(variable_names)
        if variable_names is not None
        else [variable.name for variable in discovered]
    )
    ambiguous = {name for name, count in Counter(requested).items() if count != 1}
    discovered_counts = Counter(variable.name for variable in discovered)
    ambiguous.update(name for name, count in discovered_counts.items() if count > 1)
    return FunctionAnalysis(
        tuple(variable for variable in discovered if variable.name),
        exact_function_found,
        function.has_error,
        tuple(sorted(ambiguous)),
    )


def variable_occurrence_lines(
    code: str,
    function_name: str,
    variable_names: Iterable[str],
    *,
    require_exact_function_name: bool = False,
) -> dict[str, tuple[int, ...]]:
    """Locate unambiguous local-variable identifiers in exact rendered C."""

    source = code.encode("utf-8", "replace")
    tree = _parser().parse(source)
    if require_exact_function_name:
        exact = [
            node
            for node in _walk(tree.root_node)
            if node.type == "function_definition" and _function_name(node, source) == function_name
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
