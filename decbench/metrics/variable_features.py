"""Type-blind C usage features for local-variable correspondence."""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import tree_sitter_c
from tree_sitter import Language, Node, Parser

_C_LANGUAGE = Language(tree_sitter_c.language())
_SYNTHETIC_CALLEE = re.compile(
    r"^(?:(?:thunk_|j_)?(?:fun|sub|function)_[0-9a-f]+|"
    r"(?:thunk_|j_)?fcn[._][0-9a-f]+|thunk_[0-9a-f]+)$",
    re.IGNORECASE,
)
_PSEUDO_CALLEE_RULES = (
    (re.compile(r"^_*ror\d+_*$", re.IGNORECASE), "pseudo:rotate-right"),
    (re.compile(r"^_*rol\d+_*$", re.IGNORECASE), "pseudo:rotate-left"),
    (re.compile(r"^_*zext\d+_*$", re.IGNORECASE), "pseudo:zero-extend"),
    (re.compile(r"^_*sext\d+_*$", re.IGNORECASE), "pseudo:sign-extend"),
    (re.compile(r"^_*s?pair\d+_*$", re.IGNORECASE), "pseudo:concatenate"),
    (re.compile(r"^_*coerce(?:_[a-z0-9]+)*_*$", re.IGNORECASE), "pseudo:coerce"),
    (re.compile(r"^concat\d+$", re.IGNORECASE), "pseudo:concatenate"),
    (re.compile(r"^sub\d+$", re.IGNORECASE), "pseudo:subpiece"),
    (re.compile(r"^s?carry\d+$", re.IGNORECASE), "pseudo:carry"),
    (re.compile(r"^s?borrow\d+$", re.IGNORECASE), "pseudo:borrow"),
    (re.compile(r"^_*bittest\d+_*$", re.IGNORECASE), "pseudo:bit-test"),
    (
        re.compile(r"^__read(?:fs|gs)(?:byte|word|dword|qword)$", re.IGNORECASE),
        "pseudo:segment-read",
    ),
    (
        re.compile(r"^s?(?:lo|hi)?(?:byte|word|dword|qword)\d*$", re.IGNORECASE),
        "pseudo:extract-piece",
    ),
)
_INTEGER_SUFFIX = re.compile(r"(?i)(?:u|l)+$")
_GENERIC_FEATURES = frozenset({"use:read", "use:write", "use:readwrite"})
_COMMUTATIVE_OPERATORS = frozenset({"+", "*", "&", "|", "^", "==", "!=", "&&", "||"})


@dataclass(frozen=True)
class DiscoveredVariable:
    """One declaration recovered from decompiled C without backend metadata."""

    name: str
    kind: str
    arg_index: int | None


@dataclass(frozen=True)
class UsageAnalysis:
    """Declaration discovery and name-free usage vectors for one C function."""

    variables: tuple[DiscoveredVariable, ...]
    features: dict[str, tuple[tuple[str, int], ...]]
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


def _normalized_operator(node: Node, source: bytes) -> str:
    operator = node.child_by_field_name("operator")
    if operator is not None:
        return _text(operator, source).strip()
    named_ranges = {(child.start_byte, child.end_byte) for child in node.named_children}
    for child in node.children:
        if (child.start_byte, child.end_byte) not in named_ranges:
            text = _text(child, source).strip()
            if text and text not in {"(", ")", "[", "]", "{", "}", ",", ";"}:
                return text
    return "unknown"


def _contains(ancestor: Node, descendant: Node) -> bool:
    return ancestor.start_byte <= descendant.start_byte and descendant.end_byte <= ancestor.end_byte


def _operand_role(expression: Node, occurrence: Node) -> str:
    left = expression.child_by_field_name("left")
    right = expression.child_by_field_name("right")
    if left is not None and _contains(left, occurrence):
        return "lhs"
    if right is not None and _contains(right, occurrence):
        return "rhs"
    argument = expression.child_by_field_name("argument")
    if argument is not None and _contains(argument, occurrence):
        return "arg"
    return "operand"


def _literal_feature(node: Node, source: bytes) -> str | None:
    if node.type == "string_literal":
        digest = hashlib.sha256(source[node.start_byte : node.end_byte]).hexdigest()[:12]
        return f"literal:string:{digest}"
    if node.type == "char_literal":
        digest = hashlib.sha256(source[node.start_byte : node.end_byte]).hexdigest()[:12]
        return f"literal:char:{digest}"
    if node.type != "number_literal":
        return None
    raw = _INTEGER_SUFFIX.sub("", _text(node, source).replace("'", "").strip())
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+", raw):
        value = int(raw, 16)
    elif re.fullmatch(r"0[bB][01]+", raw):
        value = int(raw, 2)
    elif len(raw) > 1 and re.fullmatch(r"0[0-7]+", raw):
        value = int(raw, 8)
    elif re.fullmatch(r"[0-9]+", raw):
        value = int(raw, 10)
    else:
        return None
    parent = node.parent
    if (
        parent is not None
        and parent.type == "unary_expression"
        and _normalized_operator(parent, source) == "-"
    ):
        value = -value
    if value in {-1, 0, 1}:
        return f"literal:number:{value}"
    absolute = abs(value)
    if absolute <= 1 << 20:
        return f"literal:number:exact:{value}"
    return f"literal:number:large:{absolute.bit_length()}"


def _direct_literal_nodes(node: Node | None) -> tuple[Node, ...]:
    if node is None:
        return ()
    if node.type in {"number_literal", "string_literal", "char_literal"}:
        return (node,)
    if node.type in {"parenthesized_expression", "unary_expression"}:
        argument = node.child_by_field_name("argument")
        if argument is None and len(node.named_children) == 1:
            argument = node.named_children[0]
        return _direct_literal_nodes(argument)
    return ()


def _related_literal_nodes(occurrence: Node, function: Node) -> tuple[Node, ...]:
    related: dict[tuple[int, int], Node] = {}
    current = occurrence.parent
    while current is not None and current != function:
        candidate = None
        if current.type in {"binary_expression", "assignment_expression"}:
            left = current.child_by_field_name("left")
            right = current.child_by_field_name("right")
            if left is not None and _contains(left, occurrence):
                candidate = right
            elif right is not None and _contains(right, occurrence):
                candidate = left
        elif current.type == "subscript_expression":
            index = current.child_by_field_name("argument")
            if index is not None and not _contains(index, occurrence):
                candidate = index
        for literal in _direct_literal_nodes(candidate):
            related[(literal.start_byte, literal.end_byte)] = literal
        current = current.parent
    return tuple(related.values())


def _argument_position(arguments: Node, occurrence: Node) -> tuple[int, int] | None:
    values = [child for child in arguments.named_children if child.type != "comment"]
    for index, value in enumerate(values):
        if _contains(value, occurrence):
            return index, len(values)
    return None


def _direct_callee(call: Node, source: bytes, local_names: set[str]) -> str | None:
    callee = call.child_by_field_name("function")
    if callee is None or callee.type != "identifier":
        return None
    name = _text(callee, source)
    if name in local_names or _SYNTHETIC_CALLEE.match(name):
        return None
    for pattern, replacement in _PSEUDO_CALLEE_RULES:
        if pattern.match(name):
            return replacement
    return name


def _call_result_features(
    expression: Node,
    source: bytes,
    local_names: set[str],
) -> Counter[str]:
    features: Counter[str] = Counter()
    call = expression
    while call.type in {"parenthesized_expression", "cast_expression"}:
        value = call.child_by_field_name("value")
        if value is None and len(call.named_children) == 1:
            value = call.named_children[0]
        if value is None:
            return features
        call = value
    if call.type != "call_expression":
        return features
    features["call:any:return_target"] += 1
    callee = _direct_callee(call, source, local_names)
    if callee is not None:
        features[f"call:named:{callee}:return_target"] += 1
    return features


def _is_unevaluated(occurrence: Node, function: Node) -> bool:
    current = occurrence.parent
    while current is not None and current != function:
        if current.type in {"sizeof_expression", "alignof_expression"}:
            return True
        current = current.parent
    return False


def _usage_role(occurrence: Node) -> str:
    parent = occurrence.parent
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left == occurrence:
            operator = parent.child_by_field_name("operator")
            return "write" if operator is not None and operator.type == "=" else "readwrite"
    if parent is not None and parent.type == "update_expression":
        return "readwrite"
    return "read"


def _features_for_occurrence(
    occurrence: Node,
    function: Node,
    source: bytes,
    local_names: set[str],
) -> Counter[str]:
    features: Counter[str] = Counter({f"use:{_usage_role(occurrence)}": 1})
    current = occurrence.parent
    while current is not None and current != function:
        kind = current.type
        if kind == "assignment_expression":
            operator = _normalized_operator(current, source)
            role = _operand_role(current, occurrence)
            features[f"assign:{operator}:{role}"] += 1
            right = current.child_by_field_name("right")
            left = current.child_by_field_name("left")
            if left == occurrence and right is not None:
                features.update(_call_result_features(right, source, local_names))
        elif kind == "binary_expression":
            operator = _normalized_operator(current, source)
            role = (
                "commutative"
                if operator in _COMMUTATIVE_OPERATORS
                else _operand_role(current, occurrence)
            )
            features[f"binary:{operator}:{role}"] += 1
        elif kind in {"unary_expression", "pointer_expression", "update_expression"}:
            operator = _normalized_operator(current, source)
            features[f"unary:{operator}:{_operand_role(current, occurrence)}"] += 1
        elif kind == "subscript_expression":
            argument = current.child_by_field_name("argument")
            role = "index" if argument is not None and _contains(argument, occurrence) else "base"
            features[f"memory:subscript:{role}"] += 1
        elif kind == "field_expression":
            argument = current.child_by_field_name("argument")
            if argument is not None and _contains(argument, occurrence):
                features["memory:field:base"] += 1
        elif kind == "cast_expression":
            value = current.child_by_field_name("value")
            if value is not None and _contains(value, occurrence):
                features["operation:cast"] += 1
        elif kind == "call_expression":
            callee_node = current.child_by_field_name("function")
            if callee_node is not None and _contains(callee_node, occurrence):
                features["call:indirect:callee"] += 1
            else:
                arguments = current.child_by_field_name("arguments")
                position = (
                    _argument_position(arguments, occurrence) if arguments is not None else None
                )
                if position is not None:
                    index, arity = position
                    features[f"call:any:arg:{index}"] += 1
                    features[f"call:arity:{arity}:arg:{index}"] += 1
                    callee = _direct_callee(current, source, local_names)
                    if callee is not None:
                        features[f"call:named:{callee}:arg:{index}"] += 1
        elif kind in {"if_statement", "while_statement", "do_statement", "switch_statement"}:
            condition = current.child_by_field_name("condition")
            if condition is not None and _contains(condition, occurrence):
                label = (
                    "loop" if kind in {"while_statement", "do_statement"} else kind.split("_")[0]
                )
                features[f"control:{label}:condition"] += 1
        elif kind == "for_statement":
            for field in ("initializer", "condition", "update"):
                value = current.child_by_field_name(field)
                if value is not None and _contains(value, occurrence):
                    features[f"control:for:{field}"] += 1
        elif kind == "return_statement":
            features["control:return:value"] += 1
        current = current.parent

    for node in _related_literal_nodes(occurrence, function):
        literal = _literal_feature(node, source)
        if literal is not None:
            features[literal] += 1
    return features


def _declaration_initializer(identifier: Node) -> Node | None:
    node = identifier.parent
    while node is not None and node.type not in {"declaration", "parameter_declaration"}:
        if node.type == "init_declarator":
            return node.child_by_field_name("value")
        node = node.parent
    return None


def analyze_c_function(
    code: str,
    function_name: str,
    variable_names: Iterable[str] | None = None,
) -> UsageAnalysis:
    """Discover locals and extract type/address/name-blind usage features."""

    source = code.encode("utf-8", "replace")
    tree = _parser().parse(source)
    function = _select_function(tree.root_node, source, function_name)
    exact_function_found = function is not None
    if function is None:
        definitions = [node for node in _walk(tree.root_node) if node.type == "function_definition"]
        if definitions:
            return UsageAnalysis((), {}, False, tree.root_node.has_error, ())
        source = _wrapped_fragment(code).encode("utf-8", "replace")
        tree = _parser().parse(source)
        function = _select_function(tree.root_node, source, "__decbench_fragment")
        if function is None:
            return UsageAnalysis((), {}, False, tree.root_node.has_error, ())

    discovered, declaration_nodes, binding_ranges = _discover_variables(function, source)
    requested = (
        list(variable_names)
        if variable_names is not None
        else [variable.name for variable in discovered]
    )
    counts = Counter(requested)
    ambiguous = {name for name, count in counts.items() if count != 1}
    discovered_counts = Counter(variable.name for variable in discovered)
    ambiguous.update(name for name, count in discovered_counts.items() if count > 1)
    target_names = {name for name in requested if name and name not in ambiguous}
    local_names = target_names | {variable.name for variable in discovered}
    features: dict[str, Counter[str]] = {name: Counter() for name in target_names}

    for node in _walk(function):
        if node.type != "identifier":
            continue
        name = _text(node, source)
        if name not in target_names:
            continue
        ranges = binding_ranges.get(name)
        if ranges and not any(start <= node.start_byte < end for start, end in ranges):
            continue
        if _is_unevaluated(node, function):
            continue
        if node in declaration_nodes:
            initializer = _declaration_initializer(node)
            if initializer is not None:
                features[name]["use:write"] += 1
                features[name]["assign:=:lhs"] += 1
                features[name].update(_call_result_features(initializer, source, local_names))
                for descendant in _direct_literal_nodes(initializer):
                    literal = _literal_feature(descendant, source)
                    if literal is not None:
                        features[name][literal] += 1
            continue
        if _field_name(node) in {"declarator", "field", "label"}:
            continue
        features[name].update(_features_for_occurrence(node, function, source, local_names))

    candidate_variables = tuple(variable for variable in discovered if variable.name)
    frozen = {
        name: tuple(sorted((feature, count) for feature, count in values.items() if count > 0))
        for name, values in features.items()
    }
    return UsageAnalysis(
        candidate_variables,
        frozen,
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


def is_context_feature(feature: str) -> bool:
    """Whether a feature carries more evidence than a generic read/write role."""

    return feature not in _GENERIC_FEATURES and feature != "literal:number:unknown"


def feature_reliability(feature: str) -> float:
    """Fixed reliability prior for one usage-feature family."""

    if feature.startswith(("call:named:", "literal:string:")):
        return 3.0
    if feature.startswith(
        (
            "assign:",
            "binary:",
            "unary:",
            "memory:",
            "operation:",
            "control:",
            "literal:",
            "call:arity:",
        )
    ):
        return 2.0
    return 1.0
