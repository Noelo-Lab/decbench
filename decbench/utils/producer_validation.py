"""Bounded, oracle-free source defects; a clean result never proves C++ validity."""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from typing import Any

from tree_sitter import Node

from decbench.metrics.variable_features import _parse_source
from decbench.models.decompilation import ProducerLanguageContract


@dataclass(frozen=True)
class ProducerFinding:
    kind: str
    line: int
    column: int
    text: str
    previous_line: int | None = None


@dataclass(frozen=True)
class ProducerInspection:
    contract: ProducerLanguageContract
    findings: tuple[ProducerFinding, ...]
    grammar_errors: bool
    text_sha256: str

    @property
    def invalid(self) -> bool:
        return bool(self.findings)

    def evidence(self) -> dict[str, Any]:
        return {
            "version": "producer-inspection-v1",
            "contract": self.contract.model_dump(),
            "validity": "invalid_source_output" if self.invalid else "not_established",
            "grammar_errors": self.grammar_errors,
            "text_sha256": self.text_sha256,
            "findings": [asdict(finding) for finding in self.findings],
            "bounds": "Bounded source checks, not compiler validation or pseudocode semantics",
        }


def _nodes(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _tokens(root: Node, source: bytes) -> Iterator[tuple[Node, bytes]]:
    pending = [root]
    opaque = {"comment", "string_literal", "raw_string_literal", "char_literal"}
    while pending:
        node = pending.pop()
        if node.is_missing or node.type in opaque or node.type.startswith("preproc_"):
            continue
        if not node.child_count or node.type == "number_literal":
            yield node, source[node.start_byte : node.end_byte]
        else:
            pending.extend(reversed(node.children))


def _object_name(node: Node) -> Node | None:
    while node.type not in {"identifier", "field_identifier"}:
        if node.has_error or node.type in {"function_declarator", "structured_binding_declarator"}:
            return None
        child = node.child_by_field_name("declarator")
        if child is None:
            if node.type == "parenthesized_declarator" and len(node.named_children) == 1:
                child = node.named_children[0]
            else:
                return None
        node = child
    return node


def _parameters(function: Node) -> list[Node]:
    declarator = function.child_by_field_name("declarator")
    while declarator is not None:
        parameters = declarator.child_by_field_name("parameters")
        if parameters is not None:
            return [
                name
                for parameter in parameters.named_children
                if (decl := parameter.child_by_field_name("declarator")) is not None
                and (name := _object_name(decl)) is not None
            ]
        declarator = declarator.child_by_field_name("declarator")
    return []


def _declarations(block: Node, source: bytes) -> Iterator[Node]:
    explicit_types = {
        "primitive_type",
        "sized_type_specifier",
        "struct_specifier",
        "union_specifier",
        "enum_specifier",
        "class_specifier",
    }
    for declaration in block.named_children:
        if declaration.type != "declaration" or declaration.has_error:
            continue
        ty = declaration.child_by_field_name("type")
        if ty is None or ty.type not in explicit_types:
            continue
        if any(
            child.type == "storage_class_specifier"
            and source[child.start_byte : child.end_byte] == b"extern"
            for child in declaration.named_children
        ):
            continue
        for index, child in enumerate(declaration.children):
            if declaration.field_name_for_child(index) == "declarator":
                name = _object_name(child)
                if name is not None:
                    yield name


def inspect_producer(code: str, metadata: dict[str, Any] | None = None) -> ProducerInspection:
    """Reject only established defects; malformed contracts/faults propagate."""
    payload = (metadata or {}).get("output_contract")
    contract = (
        ProducerLanguageContract.model_validate(payload)
        if payload is not None
        else ProducerLanguageContract()
    )
    source = code.encode("utf-8")
    line_starts = [0] + [index + 1 for index, byte in enumerate(source) if byte == 10]
    tree = _parse_source(source)
    findings: list[ProducerFinding] = []

    def finding(kind: str, node: Node, previous: Node | None = None) -> None:
        # Byte coordinates avoid py-tree-sitter 0.26 Point.column heap corruption (#487).
        line = bisect_right(line_starts, node.start_byte)
        findings.append(
            ProducerFinding(
                kind,
                line,
                node.start_byte - line_starts[line - 1] + 1,
                source[node.start_byte : node.end_byte].decode("utf-8", "replace"),
                bisect_right(line_starts, previous.start_byte) if previous is not None else None,
            )
        )

    tokens: list[tuple[Node, bytes]] = []
    for node, text in _tokens(tree.root_node, source):
        if (
            text == b":"
            and tokens
            and tokens[-1][1] == b":"
            and tokens[-1][0].end_byte == node.start_byte
        ):
            tokens[-1] = (tokens[-1][0], b"::")
        else:
            tokens.append((node, text))
    for index, (node, text) in enumerate(tokens):
        if (
            node.type == "number_literal"
            and index > 0
            and index + 1 < len(tokens)
            and tokens[index - 1][1] == tokens[index + 1][1] == b"::"
        ):
            finding("numeric_qualified_identifier", node)
        if (
            text.startswith(b"unsupported_Iop_")
            and index >= 3
            and [token for _, token in tokens[index - 3 : index]] == [b"[", b"D", b"]"]
            and index + 1 < len(tokens)
            and tokens[index + 1][1] == b"("
        ):
            finding("unsupported_ir_placeholder", node)

    for function in _nodes(tree.root_node):
        if function.type != "function_definition":
            continue
        body = function.child_by_field_name("body")
        if body is None:
            continue
        for block in _nodes(body):
            if block.type != "compound_statement":
                continue
            seen: dict[bytes, Node] = {}
            names = (_parameters(function) if block == body else []) + list(
                _declarations(block, source)
            )
            for name in names:
                spelling = source[name.start_byte : name.end_byte]
                previous = seen.get(spelling)
                if previous is not None:
                    finding("duplicate_local_binding", name, previous)
                else:
                    seen[spelling] = name
    findings.sort(key=lambda item: (item.line, item.column, item.kind))
    return ProducerInspection(
        contract, tuple(findings), tree.root_node.has_error, hashlib.sha256(source).hexdigest()
    )
