"""Fail-closed, address-free semantic audit of local-variable matching.

The matcher scorer contains the answer it proposed and the address evidence it
used.  Reviewers must never see either.  This module therefore builds two
strictly separated layers:

* public, deduplicated source/pseudocode evidence and lightweight source-
  variable cases, distributed in deterministic whole-function reviewer shards;
* a digest-bound, mode-0600 private join containing scorer identities,
  decisions, stages, scores, and confidence.

Reviewers reconstruct a semantic source-to-decompiler *relation*.  This is
important at ``-O2`` where a source variable can be folded away, split across
several decompiler variables, or coalesced with another source variable.
Labels are joined to matcher decisions only after review and report explicit
split, merge, many-to-many, wrong-edge, and oracle-unknown outcomes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import pickle
import random
import re
import secrets
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from decbench.caching import stable_hash
from decbench.experimental.local_variable_distance import (
    VariableEvidence,
    extract_decompiler_evidence,
    extract_source_evidence,
    load_source_lines,
)
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.utils.source_extract import extract_from_text

SCHEMA_VERSION = 2
DEFAULT_AUDIT_SEED = "coreutils-local-variable-semantic-audit-v2"
DEFAULT_SHARD_COUNT = 8

EVIDENCE_FILENAME = "audit_evidence.jsonl"
CASE_FILENAME = "audit_cases.jsonl"
PRIVATE_JOIN_FILENAME = "matcher_join.private.jsonl"
ALIAS_SECRET_FILENAME = "alias_secret.private.json"
LABEL_FILENAME = "audit_labels.jsonl"
MANIFEST_FILENAME = "manifest.json"
SHARD_DIRNAME = "reviewer_shards"
SHARD_MANIFEST_FILENAME = "manifest.json"
MERGE_PROVENANCE_FILENAME = "label_merge_provenance.json"
JOINED_FILENAME = "joined_results.jsonl"
REPORT_FILENAME = "report.json"

EVIDENCE_KIND = "local-variable-semantic-audit-evidence"
CASE_KIND = "local-variable-semantic-audit-case"
PRIVATE_KIND = "local-variable-semantic-audit-private-join"
PACKAGE_KIND = "local-variable-semantic-audit"
SHARD_KIND = "local-variable-semantic-audit-reviewer-shard"
SHARD_MANIFEST_KIND = "local-variable-semantic-audit-shard-manifest"
MERGE_KIND = "local-variable-semantic-audit-label-merge"
ALIAS_SECRET_KIND = "local-variable-semantic-audit-alias-secret"

ORACLE_STATUSES = {"mapped", "none_recovered", "oracle_unknown"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
BACKEND_STATUSES = {"ok", "missing", "error", "source_error"}
MATCH_CLASSIFICATIONS = {
    "correct",
    "incorrect",
    "split",
    "merge",
    "many-to-many",
    "oracle-unknown",
    "unlabeled",
}

# These boundaries are frozen before labels are inspected and copied into the
# package manifest.  Validation rejects a package that changes them.
FROZEN_BIN_VERSION = "local-variable-semantic-audit-bins-v1"
FROZEN_SCORE_BOUNDS = (0.25, 0.5, 0.75, 0.9, 0.99)
FROZEN_MINIMUM_GAP_BOUNDS = (0.01, 0.03, 0.05, 0.1, 0.25)

# Exact structured matcher evidence keys forbidden from public evidence/cases.
# Human-readable source/decompiler line numbers are permitted.
FORBIDDEN_PUBLIC_KEYS = {
    "accepted_matches",
    "accepted_target",
    "address",
    "addresses",
    "arg_index",
    "candidates",
    "checkpoint_evidence_id",
    "decompiled_id",
    "end",
    "identity",
    "intersection",
    "line_addresses",
    "line_mappings",
    "matcher",
    "matching",
    "partition",
    "run_binding_sha256",
    "sample_id",
    "score",
    "source_id",
    "stack_offset",
    "stack_offsets",
    "stage",
    "start",
    "target",
    "unmatched_decompiled",
    "unmatched_source",
}


@dataclass(frozen=True)
class CheckpointEntry:
    """One exact backend/function entry loaded from the trusted checkpoint."""

    optimization: str
    binary: str
    backend_id: str
    function: FunctionDecompilation
    result: DecompilationResult


@dataclass(frozen=True)
class DecompiledAuditEvidence:
    """Public anonymized rendering and its private identity maps."""

    public: dict[str, Any]
    alias_to_ids: dict[str, tuple[str, ...]]
    id_to_alias: dict[str, str]
    structured_evidence: dict[str, Any] | None = None
    dropped_addresses: tuple[int, ...] = ()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def evidence_sha256(value: Any) -> str:
    """Canonical JSON SHA-256 used for every public/private binding."""

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text(path: Path, text: str, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text)
    if private:
        temporary.chmod(0o600)
    temporary.replace(path)
    if private:
        path.chmod(0o600)


def write_json(path: Path, value: Any, *, private: bool = False) -> None:
    _write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        private=private,
    )


def write_jsonl(
    path: Path,
    rows: Iterable[Mapping[str, Any]],
    *,
    private: bool = False,
) -> None:
    text = "".join(
        json.dumps(
            dict(row),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
        for row in rows
    )
    _write_text(path, text, private=private)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    for line_number, text in enumerate(lines, start=1):
        if not text.strip():
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        rows.append(row)
    return rows


def _require_schema(row: Mapping[str, Any], kind: str, where: str) -> None:
    if row.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"{where}: unsupported schema_version {row.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION}"
        )
    if row.get("kind") != kind:
        raise ValueError(f"{where}: expected kind {kind!r}, got {row.get('kind')!r}")


def _require_exact_keys(
    row: Mapping[str, Any],
    expected: set[str],
    where: str,
) -> None:
    actual = set(row)
    if actual != expected:
        raise ValueError(
            f"{where}: schema fields differ; "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _alias_secret_commitment(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _parse_alias_secret(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read and validate the private per-package alias key."""

    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"alias secret is missing: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"alias secret must be a regular non-symlink file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError(f"alias secret must have mode 0600: {path}")
    payload = _read_json(path)
    _require_schema(payload, ALIAS_SECRET_KIND, "alias secret")
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "kind",
            "secret_hex",
            "commitment_sha256",
        },
        "alias secret",
    )
    secret_hex = payload.get("secret_hex")
    if not isinstance(secret_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", secret_hex):
        raise ValueError("alias secret must contain exactly 32 lowercase-hex bytes")
    secret = bytes.fromhex(secret_hex)
    expected = _alias_secret_commitment(secret)
    claimed = payload.get("commitment_sha256")
    if not isinstance(claimed, str) or not hmac.compare_digest(claimed, expected):
        raise ValueError("alias secret commitment mismatch")
    return secret, payload


def _load_or_create_alias_secret(output_dir: Path) -> tuple[bytes, Path]:
    """Load a package key, or create it only for a genuinely new package.

    Silent key rotation would invalidate every public identifier while making
    old reviewer labels look merely stale.  If any package artifact exists but
    the key does not, fail closed and require owner intervention.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / ALIAS_SECRET_FILENAME
    if path.exists() or path.is_symlink():
        secret, _payload = _parse_alias_secret(path)
        return secret, path
    existing = sorted(child.name for child in output_dir.iterdir())
    if existing:
        raise ValueError(
            "alias secret is missing from an existing audit package; refusing "
            f"silent key rotation (existing entries: {existing[:5]})"
        )
    secret = secrets.token_bytes(32)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": ALIAS_SECRET_KIND,
        "secret_hex": secret.hex(),
        "commitment_sha256": _alias_secret_commitment(secret),
    }
    write_json(path, payload, private=True)
    loaded, _stored = _parse_alias_secret(path)
    if not hmac.compare_digest(loaded, secret):
        raise ValueError("new alias secret failed its write/read integrity check")
    return secret, path


def _read_alias_secret(package_dir: Path) -> tuple[bytes, Path]:
    path = package_dir / ALIAS_SECRET_FILENAME
    secret, _payload = _parse_alias_secret(path)
    return secret, path


def _opaque_id(
    secret: bytes,
    domain: str,
    *parts: Any,
    prefix: str,
    length: int,
) -> str:
    """Return a package-keyed, non-enumerable public identifier."""

    if len(secret) != 32:
        raise ValueError("alias secret must be exactly 32 bytes")
    if length <= 0 or length > hashlib.sha256().digest_size * 2:
        raise ValueError("opaque identifier length is invalid")
    message = _canonical_bytes([domain, *parts])
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{prefix}{digest[:length]}"


def load_scorer_records(
    scorer_path: Path,
    aggregate_path: Path,
    checkpoint_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    """Load scorer rows and verify the scorer/checkpoint/aggregate run binding."""

    records = read_jsonl(scorer_path)
    seen: set[str] = set()
    for row_number, row in enumerate(records, start=1):
        sample_id = row.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ValueError(f"{scorer_path}:{row_number}: missing sample_id")
        if sample_id in seen:
            raise ValueError(f"{scorer_path}:{row_number}: duplicate sample_id {sample_id}")
        seen.add(sample_id)
    aggregate = _read_json(aggregate_path)
    # This is the scorer-owned canonical validator.  It verifies the checkpoint
    # digest, config, strict universe, selected sample, exact decompiler list,
    # per-row run binding, and scorer JSONL serialization digest.
    from decbench.experimental.local_variable_checkpoint import validate_run_provenance

    validated = validate_run_provenance(aggregate, checkpoint_path, records)
    return records, aggregate, validated


def _optimization_name(value: Any) -> str:
    return str(getattr(value, "value", value))


class CheckpointIndex:
    """Exact checkpoint lookup; no basename or base-backend fallback."""

    def __init__(self, checkpoint_path: Path) -> None:
        import decbench.decompilers  # noqa: F401
        import decbench.metrics  # noqa: F401

        try:
            payload = pickle.loads(checkpoint_path.read_bytes())
        except FileNotFoundError as exc:
            raise ValueError(f"checkpoint does not exist: {checkpoint_path}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"could not load checkpoint {checkpoint_path}: {exc}") from exc
        decompile = payload.get("decompile") if isinstance(payload, dict) else None
        if not isinstance(decompile, dict):
            raise ValueError(f"{checkpoint_path}: no decompile result dictionary")

        self._by_key: dict[
            tuple[str, str, int, str, str],
            CheckpointEntry,
        ] = {}
        for optimization, binary_rows in decompile.items():
            if not isinstance(binary_rows, dict):
                continue
            for binary, backend_rows in binary_rows.items():
                if not isinstance(backend_rows, dict):
                    continue
                for backend_id, result in backend_rows.items():
                    if not isinstance(result, DecompilationResult):
                        continue
                    for function in result.functions.values():
                        key = (
                            _optimization_name(optimization),
                            str(binary),
                            int(function.address),
                            str(function.name),
                            str(backend_id),
                        )
                        if key in self._by_key:
                            raise ValueError(f"duplicate checkpoint evidence key {key!r}")
                        self._by_key[key] = CheckpointEntry(
                            optimization=key[0],
                            binary=key[1],
                            backend_id=key[4],
                            function=function,
                            result=result,
                        )

    def find_exact(
        self,
        *,
        optimization: str,
        binary: str,
        address: int,
        name: str,
        backend_id: str,
    ) -> CheckpointEntry | None:
        return self._by_key.get((optimization, binary, address, name, backend_id))


def _parse_address(value: Any, *, field: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"invalid {field}: {value!r}") from exc
    raise ValueError(f"invalid {field}: {value!r}")


def _resolve_artifact(
    record: Mapping[str, Any],
    key: str,
    scorer_path: Path,
) -> Path:
    artifacts = record.get("artifacts")
    raw = artifacts.get(key) if isinstance(artifacts, dict) else None
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"sample {record.get('sample_id')}: missing artifact {key}")
    path = Path(raw).expanduser()
    function = record.get("function", {})
    compiled = (
        scorer_path.parent
        / str(function.get("optimization", ""))
        / str(function.get("project", ""))
        / "compiled"
    )
    candidates = [path, Path.cwd() / path, scorer_path.parent / path, compiled / path.name]
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file():
            return resolved
    raise ValueError(f"sample {record.get('sample_id')}: could not resolve {key} artifact {raw!r}")


def _observable(variable: Mapping[str, Any]) -> bool:
    return bool(
        variable.get("addresses")
        or variable.get("stack_offsets")
        or variable.get("arg_index") is not None
    )


def _non_name_evidence(value: Mapping[str, Any], where: str) -> dict[str, Any]:
    """Normalize only the fields intentionally blinded by the scorer."""

    normalized = json.loads(json.dumps(dict(value)))
    variables = normalized.get("variables")
    if not isinstance(variables, list) or any(not isinstance(row, dict) for row in variables):
        raise ValueError(f"{where}: malformed variable evidence")
    normalized["code"] = ""
    for variable in variables:
        variable["name"] = "<blinded>"
    normalized["variables"] = sorted(variables, key=lambda row: str(row.get("identity", "")))
    return normalized


def _require_same_non_name_evidence(
    scorer: Mapping[str, Any],
    reconstructed: Mapping[str, Any],
    where: str,
) -> None:
    if _non_name_evidence(scorer, where) != _non_name_evidence(reconstructed, where):
        raise ValueError(
            f"{where}: scorer evidence differs from current artifact reconstruction "
            "outside intentionally blinded names/code"
        )


def _source_type_candidates(
    binary_path: Path,
    function_name: str,
    function_address: int,
) -> dict[str, list[str]]:
    from elftools.elf.elffile import ELFFile

    from decbench.experimental.local_variable_distance import _die_name, _die_ranges
    from decbench.metrics.type_match import _parse_type_die

    result: dict[str, list[str]] = {}
    with binary_path.open("rb") as stream:
        dwarfinfo = ELFFile(stream).get_dwarf_info()
        function_die = None
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != function_name:
                    continue
                if any(begin == function_address for begin, _end in _die_ranges(die, dwarfinfo)):
                    function_die = die
                    break
            if function_die is not None:
                break
        if function_die is None:
            return result

        def walk(parent: Any) -> None:
            for child in parent.iter_children():
                if child.tag == "DW_TAG_inlined_subroutine":
                    continue
                if child.tag == "DW_TAG_lexical_block":
                    walk(child)
                    continue
                if child.tag not in {"DW_TAG_formal_parameter", "DW_TAG_variable"}:
                    continue
                try:
                    names, _size = _parse_type_die(child, dwarfinfo)
                except Exception:  # noqa: BLE001
                    names = []
                result[f"dwarf:0x{child.offset:x}"] = sorted(
                    {str(name).strip() for name in names if str(name).strip()}
                )

        walk(function_die)
    return result


def _source_function_code(
    source_path: Path,
    preprocessed_path: Path,
    function_name: str,
    declaration_line: int | None,
) -> str:
    source_text = source_path.read_text(errors="replace")
    extracted = extract_from_text(
        source_text,
        function_name,
        decl_line=int(declaration_line or 0),
    )
    if extracted is not None:
        return extracted
    if preprocessed_path != source_path:
        extracted = extract_from_text(
            preprocessed_path.read_text(errors="replace"),
            function_name,
        )
        if extracted is not None:
            return extracted
    return ""


def _line_context(
    line_map: Mapping[tuple[str, int], str],
    *,
    filename: str,
    focus_line: int,
    radius: int,
) -> dict[str, Any]:
    basename = Path(filename).name
    return {
        "file": basename,
        "focus_line": focus_line,
        "lines": [
            {"line": number, "text": line_map.get((basename, number), "")}
            for number in range(max(1, focus_line - radius), focus_line + radius + 1)
        ],
    }


def _source_contexts(
    variable: VariableEvidence,
    line_map: Mapping[tuple[str, int], str],
    *,
    default_file: str,
    radius: int,
) -> list[dict[str, Any]]:
    requested = sorted(
        {
            line
            for line in [variable.decl_line, *variable.lines]
            if isinstance(line, int) and line > 0
        }
    )
    preferred = [
        Path(name).name
        for name in (variable.decl_file, default_file)
        if isinstance(name, str) and name
    ]
    token = (
        re.compile(r"(?<![A-Za-z0-9_])" + re.escape(variable.name) + r"(?![A-Za-z0-9_])")
        if variable.name
        else None
    )
    contexts: list[dict[str, Any]] = []
    for line in requested:
        filenames = [
            filename
            for filename, actual_line in line_map
            if actual_line == line
            and (
                token is None or token.search(line_map.get((filename, actual_line), "")) is not None
            )
        ]
        filename = next(
            (name for name in preferred if (name, line) in line_map),
            filenames[0] if filenames else preferred[0] if preferred else default_file,
        )
        contexts.append(
            _line_context(
                line_map,
                filename=filename,
                focus_line=line,
                radius=radius,
            )
        )
    return contexts


def _previous_significant_operator(code: str, offset: int) -> str:
    index = offset - 1
    while index >= 0 and code[index].isspace():
        index -= 1
    if index < 0:
        return ""
    if code[index] == ".":
        return "."
    if code[index] == ">" and index > 0 and code[index - 1] == "-":
        return "->"
    if code[index] == ":" and index > 0 and code[index - 1] == ":":
        return "::"
    return code[index]


def _replace_c_local_identifiers(
    code: str,
    replacements: Mapping[str, str],
) -> str:
    """Replace local identifier tokens while preserving strings/comments/members.

    Once a local of a spelling exists, C shadowing makes every non-member token
    of that spelling in its function scope the local.  Replacing all such
    tokens is also necessary to anonymize signatures and declarations, which
    backend use-line metadata often omits.  Member accesses (``.``, ``->``,
    and ``::``) remain untouched because they are different identifiers.
    """

    output: list[str] = []
    index = 0
    state = "code"
    while index < len(code):
        char = code[index]
        next_char = code[index + 1] if index + 1 < len(code) else ""
        if state == "line_comment":
            output.append(char)
            index += 1
            if char == "\n":
                state = "code"
            continue
        if state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend((char, next_char))
                index += 2
                state = "code"
            else:
                output.append(char)
                index += 1
            continue
        if state in {"string", "char"}:
            output.append(char)
            index += 1
            if char == "\\" and index < len(code):
                escaped = code[index]
                output.append(escaped)
                index += 1
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
            continue

        if char == "/" and next_char == "/":
            output.extend((char, next_char))
            index += 2
            state = "line_comment"
            continue
        if char == "/" and next_char == "*":
            output.extend((char, next_char))
            index += 2
            state = "block_comment"
            continue
        if char == '"':
            output.append(char)
            index += 1
            state = "string"
            continue
        if char == "'":
            output.append(char)
            index += 1
            state = "char"
            continue
        if char == "\n":
            output.append(char)
            index += 1
            continue
        if char == "_" or char.isalpha():
            end = index + 1
            while end < len(code) and (code[end] == "_" or code[end].isalnum()):
                end += 1
            identifier = code[index:end]
            is_member = _previous_significant_operator(code, index) in {
                ".",
                "->",
                "::",
            }
            if identifier in replacements and not is_member:
                output.append(replacements[identifier])
            else:
                output.append(identifier)
            index = end
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _code_contexts(
    code_lines: Sequence[str],
    focus_lines: Sequence[int],
    radius: int,
) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for focus in sorted({line for line in focus_lines if 1 <= line <= len(code_lines)}):
        contexts.append(
            {
                "focus_line": focus,
                "lines": [
                    {"line": number, "text": code_lines[number - 1]}
                    for number in range(
                        max(1, focus - radius),
                        min(len(code_lines), focus + radius) + 1,
                    )
                ],
            }
        )
    return contexts


def _alias_for_identity_group(
    *,
    alias_secret: bytes,
    audit_sample_id: str,
    backend_id: str,
    identities: Sequence[str],
    length: int = 12,
) -> str:
    """Derive an alias from hidden identities under the private package key."""

    if not identities or any(
        not isinstance(identity, str) or not identity for identity in identities
    ):
        raise ValueError("alias identity groups must contain nonempty identity strings")
    return _opaque_id(
        alias_secret,
        "local-variable-semantic-audit-hidden-identity-alias-v2",
        audit_sample_id,
        backend_id,
        tuple(sorted(identities)),
        prefix="dv_",
        length=length,
    )


def _decompiled_audit_evidence(
    function: FunctionDecompilation,
    result: DecompilationResult,
    *,
    backend_id: str,
    function_name: str,
    function_end: int,
    audit_sample_id: str,
    alias_secret: bytes,
    audit_seed: str,
    instruction_addresses: frozenset[int],
    context_lines: int,
    scorer_status: str,
) -> DecompiledAuditEvidence:
    evidence = extract_decompiler_evidence(
        function,
        backend=backend_id,
        function_name=function_name,
        function_end=function_end,
    )
    from decbench.experimental.local_variable_checkpoint import (
        _filter_to_function_instructions,
    )

    evidence, dropped_addresses = _filter_to_function_instructions(
        evidence,
        instruction_addresses,
    )
    by_identity = {variable.identity: variable for variable in evidence.variables}
    if len(by_identity) != len(evidence.variables):
        raise ValueError(f"{backend_id}/{function_name}: duplicate decompiler identity")

    # A rendered spelling is the only available way to rewrite code.  Multiple
    # hidden identities with that spelling form one explicitly ambiguous group.
    raw_groups: dict[str, list[VariableEvidence]] = defaultdict(list)
    for variable in evidence.variables:
        raw_groups[variable.name].append(variable)
    raw_to_alias: dict[str, str] = {}
    aliases_seen: set[str] = set()
    alias_to_ids: dict[str, tuple[str, ...]] = {}
    id_to_alias: dict[str, str] = {}
    for raw_name, variables in sorted(raw_groups.items()):
        identities = tuple(sorted(variable.identity for variable in variables))
        length = 12
        alias = _alias_for_identity_group(
            alias_secret=alias_secret,
            audit_sample_id=audit_sample_id,
            backend_id=backend_id,
            identities=identities,
            length=length,
        )
        while alias in aliases_seen:
            length += 2
            alias = _alias_for_identity_group(
                alias_secret=alias_secret,
                audit_sample_id=audit_sample_id,
                backend_id=backend_id,
                identities=identities,
                length=length,
            )
        aliases_seen.add(alias)
        raw_to_alias[raw_name] = alias
        alias_to_ids[alias] = identities
        for identity in identities:
            if identity in id_to_alias:
                raise ValueError(
                    f"{backend_id}/{function_name}: identity {identity} belongs "
                    "to more than one alias group"
                )
            id_to_alias[identity] = alias

    anonymized_code = _replace_c_local_identifiers(
        evidence.code,
        raw_to_alias,
    )
    code_lines = anonymized_code.splitlines()
    raw_infos = {
        f"{backend_id}:{index}": variable
        for index, variable in enumerate(function.variables)
        if variable.name
    }
    catalog: list[dict[str, Any]] = []
    for raw_name, variables in raw_groups.items():
        alias = raw_to_alias[raw_name]
        identities = alias_to_ids[alias]
        infos = [raw_infos[identity] for identity in identities if identity in raw_infos]
        focus_lines = sorted({line for variable in variables for line in variable.lines})
        catalog.append(
            {
                "audit_id": alias,
                "roles": sorted({variable.kind for variable in variables}),
                "type_candidates": sorted(
                    {str(info.type).strip() for info in infos if str(info.type).strip()}
                ),
                "sizes_bytes": sorted({int(info.size) for info in infos if info.size is not None}),
                "use_lines": focus_lines,
                "contexts": _code_contexts(code_lines, focus_lines, context_lines),
                "alias_group_size": len(identities),
                "ambiguous_alias": len(identities) != 1,
            }
        )
    catalog.sort(
        key=lambda row: stable_hash(
            "local-variable-semantic-audit-catalog-order-v2",
            audit_seed,
            audit_sample_id,
            backend_id,
            row["audit_id"],
        )
    )
    version = result.decompiler.decompiler_version
    return DecompiledAuditEvidence(
        public={
            "backend_id": backend_id,
            "status": scorer_status,
            "version": str(version) if version is not None else None,
            "code": anonymized_code,
            "variables": catalog,
        },
        alias_to_ids=alias_to_ids,
        id_to_alias=id_to_alias,
        structured_evidence=evidence.to_dict(),
        dropped_addresses=dropped_addresses,
    )


def _missing_decompiled_evidence(
    backend_id: str,
    status: str,
) -> DecompiledAuditEvidence:
    return DecompiledAuditEvidence(
        public={
            "backend_id": backend_id,
            "status": status,
            "version": None,
            "code": "",
            "variables": [],
        },
        alias_to_ids={},
        id_to_alias={},
        structured_evidence=None,
    )


def _walk_public_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in FORBIDDEN_PUBLIC_KEYS:
                raise ValueError(f"public audit data leaks forbidden key {path}.{key}")
            _walk_public_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _walk_public_keys(nested, f"{path}[{index}]")


def _require_string(value: Any, where: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{where}: expected {'a ' if not allow_empty else ''}string")
    return value


def _require_optional_int(value: Any, where: str) -> None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{where}: expected an integer or null")


def _validate_line_rows(rows: Any, where: str) -> None:
    if not isinstance(rows, list):
        raise ValueError(f"{where}: lines must be a list")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{where}.lines[{index}]: expected an object")
        _require_exact_keys(row, {"line", "text"}, f"{where}.lines[{index}]")
        if not isinstance(row["line"], int) or isinstance(row["line"], bool):
            raise ValueError(f"{where}.lines[{index}].line: expected an integer")
        _require_string(row["text"], f"{where}.lines[{index}].text", allow_empty=True)


def _validate_contexts(value: Any, where: str, *, source: bool) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{where}: expected a list")
    expected = {"focus_line", "lines", "file"} if source else {"focus_line", "lines"}
    for index, context in enumerate(value):
        if not isinstance(context, dict):
            raise ValueError(f"{where}[{index}]: expected an object")
        _require_exact_keys(context, expected, f"{where}[{index}]")
        if not isinstance(context["focus_line"], int) or isinstance(context["focus_line"], bool):
            raise ValueError(f"{where}[{index}].focus_line: expected an integer")
        if source:
            _require_string(context["file"], f"{where}[{index}].file")
        _validate_line_rows(context["lines"], f"{where}[{index}]")


def _validate_public_evidence_schema(row: Mapping[str, Any]) -> None:
    where = f"evidence {row.get('evidence_id')}"
    _require_exact_keys(
        row,
        {
            "schema_version",
            "kind",
            "evidence_id",
            "audit_sample_id",
            "backend_id",
            "function",
            "source_function_code",
            "source_variables",
            "decompiled",
            "review_question",
            "evidence_sha256",
        },
        where,
    )
    for field in ("evidence_id", "audit_sample_id", "backend_id", "source_function_code"):
        _require_string(
            row[field],
            f"{where}.{field}",
            allow_empty=field == "source_function_code",
        )
    _require_string(row["review_question"], f"{where}.review_question")
    function = row["function"]
    if not isinstance(function, dict):
        raise ValueError(f"{where}.function: expected an object")
    _require_exact_keys(
        function,
        {"project", "optimization", "binary", "name"},
        f"{where}.function",
    )
    for field in function:
        _require_string(function[field], f"{where}.function.{field}")

    source_variables = row["source_variables"]
    if not isinstance(source_variables, list):
        raise ValueError(f"{where}.source_variables: expected a list")
    for index, variable in enumerate(source_variables):
        item_where = f"{where}.source_variables[{index}]"
        if not isinstance(variable, dict):
            raise ValueError(f"{item_where}: expected an object")
        _require_exact_keys(
            variable,
            {
                "audit_id",
                "name",
                "role",
                "size_bytes",
                "type_candidates",
                "declaration",
                "contexts",
            },
            item_where,
        )
        for field in ("audit_id", "name", "role"):
            _require_string(variable[field], f"{item_where}.{field}")
        _require_optional_int(variable["size_bytes"], f"{item_where}.size_bytes")
        if not isinstance(variable["type_candidates"], list) or any(
            not isinstance(candidate, str) for candidate in variable["type_candidates"]
        ):
            raise ValueError(f"{item_where}.type_candidates: expected a string list")
        declaration = variable["declaration"]
        if not isinstance(declaration, dict):
            raise ValueError(f"{item_where}.declaration: expected an object")
        _require_exact_keys(declaration, {"file", "line"}, f"{item_where}.declaration")
        _require_string(declaration["file"], f"{item_where}.declaration.file")
        _require_optional_int(declaration["line"], f"{item_where}.declaration.line")
        _validate_contexts(variable["contexts"], f"{item_where}.contexts", source=True)

    decompiled = row["decompiled"]
    if not isinstance(decompiled, dict):
        raise ValueError(f"{where}.decompiled: expected an object")
    _require_exact_keys(
        decompiled,
        {"backend_id", "status", "version", "code", "variables"},
        f"{where}.decompiled",
    )
    if decompiled["backend_id"] != row["backend_id"]:
        raise ValueError(f"{where}: decompiled backend does not match evidence backend")
    if decompiled["status"] not in BACKEND_STATUSES - {"source_error"}:
        raise ValueError(f"{where}.decompiled.status: invalid status")
    if decompiled["version"] is not None:
        _require_string(decompiled["version"], f"{where}.decompiled.version")
    _require_string(decompiled["code"], f"{where}.decompiled.code", allow_empty=True)
    variables = decompiled["variables"]
    if not isinstance(variables, list):
        raise ValueError(f"{where}.decompiled.variables: expected a list")
    for index, variable in enumerate(variables):
        item_where = f"{where}.decompiled.variables[{index}]"
        if not isinstance(variable, dict):
            raise ValueError(f"{item_where}: expected an object")
        _require_exact_keys(
            variable,
            {
                "audit_id",
                "roles",
                "type_candidates",
                "sizes_bytes",
                "use_lines",
                "contexts",
                "alias_group_size",
                "ambiguous_alias",
            },
            item_where,
        )
        _require_string(variable["audit_id"], f"{item_where}.audit_id")
        for field in ("roles", "type_candidates"):
            if not isinstance(variable[field], list) or any(
                not isinstance(value, str) for value in variable[field]
            ):
                raise ValueError(f"{item_where}.{field}: expected a string list")
        for field in ("sizes_bytes", "use_lines"):
            if not isinstance(variable[field], list) or any(
                not isinstance(value, int) or isinstance(value, bool) for value in variable[field]
            ):
                raise ValueError(f"{item_where}.{field}: expected an integer list")
        group_size = variable["alias_group_size"]
        if not isinstance(group_size, int) or isinstance(group_size, bool) or group_size <= 0:
            raise ValueError(f"{item_where}.alias_group_size: expected a positive integer")
        if not isinstance(variable["ambiguous_alias"], bool):
            raise ValueError(f"{item_where}.ambiguous_alias: expected a boolean")
        if variable["ambiguous_alias"] != (group_size != 1):
            raise ValueError(f"{item_where}: ambiguous_alias/group-size mismatch")
        _validate_contexts(variable["contexts"], f"{item_where}.contexts", source=False)


def _validate_public_case_schema(row: Mapping[str, Any]) -> None:
    where = f"case {row.get('case_id')}"
    _require_exact_keys(
        row,
        {
            "schema_version",
            "kind",
            "case_id",
            "evidence_id",
            "evidence_sha256",
            "audit_sample_id",
            "backend_id",
            "source_variable_audit_id",
            "shard_id",
            "case_sha256",
        },
        where,
    )
    for field in (
        "case_id",
        "evidence_id",
        "evidence_sha256",
        "audit_sample_id",
        "backend_id",
        "source_variable_audit_id",
        "shard_id",
        "case_sha256",
    ):
        _require_string(row[field], f"{where}.{field}")


def _validate_bound_row(
    row: Mapping[str, Any],
    *,
    kind: str,
    hash_field: str,
    where: str,
) -> None:
    _require_schema(row, kind, where)
    payload = dict(row)
    claimed = payload.pop(hash_field, None)
    if not isinstance(claimed, str) or claimed != evidence_sha256(payload):
        raise ValueError(f"{where}: {hash_field} mismatch")
    _walk_public_keys(payload)


def validate_public_evidence(row: Mapping[str, Any]) -> None:
    _validate_public_evidence_schema(row)
    _validate_bound_row(
        row,
        kind=EVIDENCE_KIND,
        hash_field="evidence_sha256",
        where=f"evidence {row.get('evidence_id')}",
    )


def validate_public_case(row: Mapping[str, Any]) -> None:
    _validate_public_case_schema(row)
    _validate_bound_row(
        row,
        kind=CASE_KIND,
        hash_field="case_sha256",
        where=f"case {row.get('case_id')}",
    )


def _evidence_variable_ids(evidence: Mapping[str, Any]) -> set[str]:
    decompiled = evidence.get("decompiled", {})
    variables = decompiled.get("variables", []) if isinstance(decompiled, dict) else []
    return {
        str(variable["audit_id"])
        for variable in variables
        if isinstance(variable, dict) and isinstance(variable.get("audit_id"), str)
    }


def _ambiguous_evidence_variable_ids(evidence: Mapping[str, Any]) -> set[str]:
    decompiled = evidence.get("decompiled", {})
    variables = decompiled.get("variables", []) if isinstance(decompiled, dict) else []
    return {
        str(variable["audit_id"])
        for variable in variables
        if isinstance(variable, dict)
        and isinstance(variable.get("audit_id"), str)
        and variable.get("ambiguous_alias") is True
    }


def _validate_evidence_case_coverage(
    evidence_by_id: Mapping[str, Mapping[str, Any]],
    cases_by_evidence: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Require one and only one case for every public source variable."""

    unknown_evidence = set(cases_by_evidence) - set(evidence_by_id)
    if unknown_evidence:
        raise ValueError(f"cases name unknown evidence IDs: {sorted(unknown_evidence)[:3]}")
    for evidence_id, evidence in evidence_by_id.items():
        expected_source_ids = [
            str(variable["audit_id"])
            for variable in evidence.get("source_variables", [])
            if isinstance(variable, dict)
        ]
        observed_cases = list(cases_by_evidence.get(evidence_id, []))
        observed_source_ids = [str(case["source_variable_audit_id"]) for case in observed_cases]
        if (
            len(observed_cases) != len(expected_source_ids)
            or len(observed_source_ids) != len(set(observed_source_ids))
            or set(observed_source_ids) != set(expected_source_ids)
        ):
            raise ValueError(
                f"evidence {evidence_id}: cases do not exactly cover each "
                "public source variable once"
            )


def _label_template(case: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "local-variable-semantic-audit-label",
        "case_id": case["case_id"],
        "case_sha256": case["case_sha256"],
        "evidence_id": case["evidence_id"],
        "evidence_sha256": case["evidence_sha256"],
        "shard_id": case["shard_id"],
        "oracle_status": None,
        "selected_decompiled_audit_ids": [],
        "confidence": None,
        "rationale": "",
        "reviewer": "",
    }


def validate_labels(
    labels: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    evidence_rows: Sequence[Mapping[str, Any]],
    *,
    require_complete: bool,
    require_full_coverage: bool = True,
    expected_case_ids: set[str] | None = None,
    reviewer_assignment: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Validate hashes, schema, state, reviewer provenance, and coverage."""

    case_by_id = {str(case["case_id"]): case for case in cases}
    if len(case_by_id) != len(cases):
        raise ValueError("audit cases contain duplicate case_id values")
    evidence_by_id = {str(evidence["evidence_id"]): evidence for evidence in evidence_rows}
    if len(evidence_by_id) != len(evidence_rows):
        raise ValueError("audit evidence contains duplicate evidence_id values")
    allowed_case_ids = expected_case_ids if expected_case_ids is not None else set(case_by_id)
    if not allowed_case_ids <= set(case_by_id):
        raise ValueError("expected label coverage contains unknown case IDs")

    by_id: dict[str, dict[str, Any]] = {}
    expected_label_fields = {
        "schema_version",
        "kind",
        "case_id",
        "case_sha256",
        "evidence_id",
        "evidence_sha256",
        "shard_id",
        "oracle_status",
        "selected_decompiled_audit_ids",
        "confidence",
        "rationale",
        "reviewer",
    }
    for row_number, raw in enumerate(labels, start=1):
        row = dict(raw)
        _require_exact_keys(row, expected_label_fields, f"label row {row_number}")
        if row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"label row {row_number}: unsupported schema_version "
                f"{row.get('schema_version')!r}"
            )
        if row.get("kind") != "local-variable-semantic-audit-label":
            raise ValueError(f"label row {row_number}: invalid kind")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or case_id not in allowed_case_ids:
            raise ValueError(f"label row {row_number}: unknown case_id {case_id!r}")
        if case_id in by_id:
            raise ValueError(f"label row {row_number}: duplicate case_id {case_id}")
        case = case_by_id[case_id]
        evidence = evidence_by_id.get(str(case.get("evidence_id")))
        if evidence is None:
            raise ValueError(f"label row {row_number}: case evidence is missing")
        for field in (
            "case_sha256",
            "evidence_id",
            "evidence_sha256",
            "shard_id",
        ):
            if row.get(field) != case.get(field):
                raise ValueError(f"label row {row_number}: stale or mismatched {field}")

        status = row.get("oracle_status")
        if status is not None and status not in ORACLE_STATUSES:
            raise ValueError(f"label row {row_number}: invalid oracle_status {status!r}")
        confidence = row.get("confidence")
        if confidence is not None and confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"label row {row_number}: invalid confidence {confidence!r}")
        selected = row.get("selected_decompiled_audit_ids")
        if not isinstance(selected, list) or any(not isinstance(value, str) for value in selected):
            raise ValueError(
                f"label row {row_number}: " "selected_decompiled_audit_ids must be strings"
            )
        if len(selected) != len(set(selected)):
            raise ValueError(f"label row {row_number}: duplicate selected audit ID")
        unknown_ids = set(selected) - _evidence_variable_ids(evidence)
        if unknown_ids:
            raise ValueError(
                f"label row {row_number}: unknown selected audit IDs " f"{sorted(unknown_ids)}"
            )
        ambiguous_ids = set(selected) & _ambiguous_evidence_variable_ids(evidence)
        if ambiguous_ids:
            raise ValueError(
                f"label row {row_number}: {sorted(ambiguous_ids)} represent "
                "multiple hidden identities; use oracle_unknown"
            )
        if status == "mapped" and not selected:
            raise ValueError(f"label row {row_number}: mapped status needs a selection")
        if status in {"none_recovered", "oracle_unknown"} and selected:
            raise ValueError(f"label row {row_number}: {status} cannot select variables")
        if status is None and selected:
            raise ValueError(f"label row {row_number}: unlabeled case cannot select variables")

        reviewer = row.get("reviewer")
        rationale = row.get("rationale")
        if not isinstance(reviewer, str) or not isinstance(rationale, str):
            raise ValueError(f"label row {row_number}: reviewer/rationale must be strings")
        if require_complete:
            if status is None:
                raise ValueError(f"label row {row_number}: oracle_status is not completed")
            if not isinstance(reviewer, str) or not reviewer.strip():
                raise ValueError(f"label row {row_number}: completed label needs reviewer")
            if reviewer_assignment is not None and reviewer != reviewer_assignment:
                raise ValueError(
                    f"label row {row_number}: reviewer does not match shard assignment"
                )
            if confidence not in CONFIDENCE_LEVELS:
                raise ValueError(f"label row {row_number}: completed label needs confidence")
            if not isinstance(rationale, str) or len(rationale.strip()) < 3:
                raise ValueError(f"label row {row_number}: completed label needs rationale")
            if status == "oracle_unknown" and len(rationale.strip()) < 20:
                raise ValueError(
                    f"label row {row_number}: oracle_unknown needs a meaningful "
                    "rationale (at least 20 characters)"
                )
        elif reviewer_assignment is not None and reviewer not in {
            "",
            reviewer_assignment,
        }:
            raise ValueError(f"label row {row_number}: reviewer conflicts with shard assignment")
        by_id[case_id] = row

    if require_full_coverage:
        missing = allowed_case_ids - set(by_id)
        extra = set(by_id) - allowed_case_ids
        if missing or extra:
            raise ValueError(f"label coverage mismatch: missing={len(missing)} extra={len(extra)}")
    return by_id


def _assign_shards(
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    shard_count: int,
) -> dict[str, str]:
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    case_counts = Counter(str(case["evidence_id"]) for case in cases)
    ordered = sorted(
        (str(evidence["evidence_id"]) for evidence in evidence_rows),
        key=lambda evidence_id: stable_hash(
            "local-variable-semantic-audit-shard-order-v1",
            evidence_id,
        ),
    )
    actual_count = min(shard_count, max(1, len(ordered)))
    loads = [0] * actual_count
    assignment: dict[str, str] = {}
    for evidence_id in ordered:
        index = min(range(actual_count), key=lambda value: (loads[value], value))
        assignment[evidence_id] = f"shard_{index:03d}"
        loads[index] += case_counts[evidence_id]
    return assignment


def _shard_public_payload(
    shard_id: str,
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": SHARD_KIND,
        "shard_id": shard_id,
        "review_instructions": {
            "task": (
                "For every lightweight case, find its source_variable_audit_id "
                "inside the referenced evidence row, then label the full semantic "
                "relation to anonymized decompiler variables."
            ),
            "statuses": {
                "mapped": "select every related dv_ audit ID",
                "none_recovered": "select no IDs",
                "oracle_unknown": (
                    "select no IDs and explain why source/pseudocode evidence "
                    "cannot support a defensible relation"
                ),
            },
            "decision_jsonl_fields": [
                "schema_version",
                "case_id",
                "oracle_status",
                "selected_decompiled_audit_ids",
                "confidence",
                "rationale",
            ],
            "safe_command": (
                "python scripts/audit_local_variable_semantics.py "
                "apply-decisions --shard THIS.json --decisions decisions.jsonl "
                "--reviewer NAME --output THIS.completed.json"
            ),
            "private_matcher_data_required": False,
        },
        "evidence": list(evidence_rows),
        "cases": list(cases),
    }


def _validate_reviewer_shard_schema(
    shard: Mapping[str, Any],
    where: str,
) -> None:
    _require_schema(shard, SHARD_KIND, where)
    _require_exact_keys(
        shard,
        {
            "schema_version",
            "kind",
            "shard_id",
            "review_instructions",
            "evidence",
            "cases",
            "public_payload_sha256",
            "reviewer_assignment",
            "labels",
        },
        where,
    )
    shard_id = _require_string(shard.get("shard_id"), f"{where}.shard_id")
    evidence_rows = shard.get("evidence")
    cases = shard.get("cases")
    labels = shard.get("labels")
    if not isinstance(evidence_rows, list) or not isinstance(cases, list):
        raise ValueError(f"{where}: evidence/cases must be lists")
    if not isinstance(labels, list):
        raise ValueError(f"{where}: labels must be a list")
    if shard.get("reviewer_assignment") is not None and not isinstance(
        shard.get("reviewer_assignment"), str
    ):
        raise ValueError(f"{where}: reviewer_assignment must be a string or null")
    expected_instructions = _shard_public_payload(shard_id, [], [])["review_instructions"]
    if shard.get("review_instructions") != expected_instructions:
        raise ValueError(f"{where}: review instructions are unsupported or changed")
    _require_string(
        shard.get("public_payload_sha256"),
        f"{where}.public_payload_sha256",
    )


def _write_reviewer_shards(
    output_dir: Path,
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    labels: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], list[Path]]:
    evidence_by_id = {str(evidence["evidence_id"]): evidence for evidence in evidence_rows}
    labels_by_id = {str(label["case_id"]): label for label in labels}
    shard_ids = sorted({str(case["shard_id"]) for case in cases})
    shard_dir = output_dir / SHARD_DIRNAME
    shard_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    entries: list[dict[str, Any]] = []
    expected_names = {f"{shard_id}.json" for shard_id in shard_ids}
    for stale in shard_dir.glob("shard_*.json"):
        if stale.name not in expected_names:
            stale.unlink()
    for shard_id in shard_ids:
        shard_cases = [case for case in cases if case["shard_id"] == shard_id]
        evidence_ids = sorted({str(case["evidence_id"]) for case in shard_cases})
        shard_evidence = [evidence_by_id[evidence_id] for evidence_id in evidence_ids]
        immutable = _shard_public_payload(shard_id, shard_evidence, shard_cases)
        payload_sha256 = evidence_sha256(immutable)
        shard = {
            **immutable,
            "public_payload_sha256": payload_sha256,
            "reviewer_assignment": None,
            "labels": [labels_by_id[str(case["case_id"])] for case in shard_cases],
        }
        path = shard_dir / f"{shard_id}.json"
        write_json(path, shard)
        written.append(path)
        entries.append(
            {
                "shard_id": shard_id,
                "file": path.name,
                "evidence_ids": evidence_ids,
                "case_ids": [str(case["case_id"]) for case in shard_cases],
                "public_payload_sha256": payload_sha256,
                "initial_file_sha256": _file_sha256(path),
            }
        )
    shard_manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": SHARD_MANIFEST_KIND,
        "shard_count": len(entries),
        "evidence_count": len(evidence_rows),
        "case_count": len(cases),
        "shards": entries,
    }
    shard_manifest = {
        **shard_manifest_payload,
        "manifest_payload_sha256": evidence_sha256(shard_manifest_payload),
    }
    path = shard_dir / SHARD_MANIFEST_FILENAME
    write_json(path, shard_manifest)
    written.append(path)
    return shard_manifest, written


def _selected_backends(
    records: Sequence[Mapping[str, Any]],
    aggregate: Mapping[str, Any],
    requested: Sequence[str] | None,
) -> list[str]:
    provenance = aggregate.get("provenance")
    available = provenance.get("decompilers") if isinstance(provenance, dict) else None
    if not isinstance(available, list) or any(
        not isinstance(value, str) or not value for value in available
    ):
        raise ValueError("aggregate provenance has no exact decompiler key list")
    if len(available) != len(set(available)):
        raise ValueError("aggregate provenance contains duplicate decompiler keys")
    expected = set(available)
    for record in records:
        entries = record.get("decompilers")
        if not isinstance(entries, dict) or set(entries) != expected:
            raise ValueError(
                f"sample {record.get('sample_id')}: backend key set does not "
                "match aggregate provenance"
            )
    if requested is None:
        return list(available)
    if len(requested) != len(set(requested)):
        raise ValueError("requested backend list contains duplicates")
    unknown = set(requested) - expected
    if unknown:
        raise ValueError(
            "requested backends are not exact checkpoint keys: "
            f"{sorted(unknown)}; available={available}"
        )
    return list(requested)


def _validate_scorer_backend(
    *,
    sample_id: str,
    backend_id: str,
    scorer_entry: Mapping[str, Any],
    checkpoint_entry: CheckpointEntry | None,
    observable_source_ids: set[str],
    decompiled: DecompiledAuditEvidence | None,
) -> list[dict[str, Any]]:
    status = scorer_entry.get("status")
    if status not in BACKEND_STATUSES:
        raise ValueError(f"sample {sample_id}/{backend_id}: unknown backend status {status!r}")
    if status == "source_error":
        raise ValueError(
            f"sample {sample_id}/{backend_id}: source_error is invalid when "
            "source extraction succeeded"
        )
    if status == "missing":
        if checkpoint_entry is not None:
            raise ValueError(
                f"sample {sample_id}/{backend_id}: scorer says missing but exact "
                "checkpoint evidence exists"
            )
        if scorer_entry.get("evidence") is not None or scorer_entry.get("matching") is not None:
            raise ValueError(f"sample {sample_id}/{backend_id}: missing status carries evidence")
        return []
    if checkpoint_entry is None:
        raise ValueError(
            f"sample {sample_id}/{backend_id}: {status} status lacks exact " "checkpoint evidence"
        )
    if status == "error":
        if scorer_entry.get("matching") is not None:
            raise ValueError(f"sample {sample_id}/{backend_id}: error status carries matching")
        return []
    if decompiled is None:
        raise ValueError(
            f"sample {sample_id}/{backend_id}: ok status has no reconstructed evidence"
        )

    evidence = scorer_entry.get("evidence")
    matching = scorer_entry.get("matching")
    if not isinstance(evidence, dict) or not isinstance(evidence.get("variables"), list):
        raise ValueError(f"sample {sample_id}/{backend_id}: ok status lacks scorer evidence")
    if not isinstance(matching, dict):
        raise ValueError(f"sample {sample_id}/{backend_id}: ok status lacks matching")
    if decompiled.structured_evidence is None:
        raise ValueError(
            f"sample {sample_id}/{backend_id}: reconstructed structured evidence is missing"
        )
    _require_same_non_name_evidence(
        evidence,
        decompiled.structured_evidence,
        f"sample {sample_id}/{backend_id}: decompiler",
    )
    address_filter = scorer_entry.get("address_filter")
    if not isinstance(address_filter, dict):
        raise ValueError(f"sample {sample_id}/{backend_id}: address filter is missing")
    _require_exact_keys(
        address_filter,
        {
            "policy",
            "boundary_merge_status",
            "dropped_count",
            "dropped_addresses",
        },
        f"sample {sample_id}/{backend_id}: address filter",
    )
    expected_dropped = [f"0x{address:x}" for address in decompiled.dropped_addresses]
    if (
        address_filter.get("policy") != "decoded instruction starts in the DWARF function range"
        or address_filter.get("dropped_count") != len(expected_dropped)
        or address_filter.get("dropped_addresses") != expected_dropped
        or address_filter.get("boundary_merge_status")
        != ("out_of_range_or_noninstruction_evidence_filtered" if expected_dropped else "none")
    ):
        raise ValueError(
            f"sample {sample_id}/{backend_id}: scorer/current-artifact "
            "instruction-filter evidence differs"
        )
    scorer_decompiled_ids = [
        variable.get("identity") for variable in evidence["variables"] if isinstance(variable, dict)
    ]
    if any(not isinstance(identity, str) or not identity for identity in scorer_decompiled_ids):
        raise ValueError(f"sample {sample_id}/{backend_id}: invalid decompiler evidence identity")
    if len(scorer_decompiled_ids) != len(set(scorer_decompiled_ids)):
        raise ValueError(f"sample {sample_id}/{backend_id}: duplicate decompiler evidence identity")
    reconstructed_ids = set(decompiled.id_to_alias)
    if set(scorer_decompiled_ids) != reconstructed_ids:
        raise ValueError(
            f"sample {sample_id}/{backend_id}: scorer/checkpoint decompiler " "identity sets differ"
        )
    if matching.get("decompiled_count") != len(reconstructed_ids):
        raise ValueError(f"sample {sample_id}/{backend_id}: decompiled_count mismatch")
    if matching.get("source_observable_count") != len(observable_source_ids):
        raise ValueError(f"sample {sample_id}/{backend_id}: observable source count mismatch")
    accepted = matching.get("accepted_matches")
    if not isinstance(accepted, list):
        raise ValueError(f"sample {sample_id}/{backend_id}: accepted_matches is not a list")
    if matching.get("accepted_count") != len(accepted):
        raise ValueError(f"sample {sample_id}/{backend_id}: accepted_count mismatch")
    source_targets: set[str] = set()
    decompiled_targets: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, match in enumerate(accepted):
        if not isinstance(match, dict):
            raise ValueError(f"sample {sample_id}/{backend_id}: accepted match {index} is invalid")
        source_id = match.get("source_id")
        decompiled_id = match.get("decompiled_id")
        if source_id not in observable_source_ids:
            raise ValueError(
                f"sample {sample_id}/{backend_id}: accepted source_id "
                f"{source_id!r} has no observable case"
            )
        if decompiled_id not in reconstructed_ids:
            raise ValueError(
                f"sample {sample_id}/{backend_id}: accepted decompiled_id "
                f"{decompiled_id!r} has no exact checkpoint alias"
            )
        if source_id in source_targets:
            raise ValueError(
                f"sample {sample_id}/{backend_id}: duplicate accepted source_id " f"{source_id}"
            )
        if decompiled_id in decompiled_targets:
            raise ValueError(
                f"sample {sample_id}/{backend_id}: duplicate accepted "
                f"decompiled_id {decompiled_id}"
            )
        source_targets.add(str(source_id))
        decompiled_targets.add(str(decompiled_id))
        normalized.append(dict(match))
    return normalized


def _source_public_variable(
    variable: VariableEvidence,
    *,
    source_audit_id: str,
    type_candidates: Mapping[str, list[str]],
    source_lines: Mapping[tuple[str, int], str],
    declaration_file: str,
    context_lines: int,
) -> dict[str, Any]:
    return {
        "audit_id": source_audit_id,
        "name": variable.name,
        "role": variable.kind,
        "size_bytes": variable.size,
        "type_candidates": type_candidates.get(variable.identity, []),
        "declaration": {
            "file": variable.decl_file or declaration_file,
            "line": variable.decl_line,
        },
        "contexts": _source_contexts(
            variable,
            source_lines,
            default_file=declaration_file,
            radius=context_lines,
        ),
    }


def build_audit_package(
    scorer_path: Path,
    checkpoint_path: Path,
    output_dir: Path,
    *,
    sample_manifest_path: Path | None = None,
    backends: Sequence[str] | None = None,
    audit_seed: str = DEFAULT_AUDIT_SEED,
    context_lines: int = 2,
    shard_count: int = DEFAULT_SHARD_COUNT,
) -> dict[str, Any]:
    """Build a provenance-bound, deduplicated public/private audit package."""

    if sample_manifest_path is None:
        raise ValueError("the scorer aggregate/report is required for provenance")
    if context_lines < 0:
        raise ValueError("context_lines must be non-negative")
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    records, aggregate, validated_provenance = load_scorer_records(
        scorer_path,
        sample_manifest_path,
        checkpoint_path,
    )
    selected_backends = _selected_backends(records, aggregate, backends)
    alias_secret, alias_secret_path = _load_or_create_alias_secret(output_dir)
    checkpoint = CheckpointIndex(checkpoint_path)
    aggregate_provenance = aggregate.get("provenance")
    score_config = (
        aggregate_provenance.get("score_config") if isinstance(aggregate_provenance, dict) else None
    )
    if not isinstance(score_config, dict) or not isinstance(
        score_config.get("include_inlined"), bool
    ):
        raise ValueError("aggregate score config has no boolean include_inlined")
    include_inlined = bool(score_config["include_inlined"])

    evidence_rows: list[dict[str, Any]] = []
    provisional_cases: list[dict[str, Any]] = []
    provisional_private: dict[str, dict[str, Any]] = {}
    source_status_counts: Counter[str] = Counter()
    backend_function_status: dict[str, Counter[str]] = {
        backend: Counter() for backend in selected_backends
    }
    backend_function_status_by_partition: dict[str, dict[str, Counter[str]]] = {
        backend: defaultdict(Counter) for backend in selected_backends
    }
    backend_case_status: dict[str, Counter[str]] = {
        backend: Counter() for backend in selected_backends
    }
    skipped_source_records: list[dict[str, Any]] = []
    zero_observable_records: list[dict[str, Any]] = []
    artifact_digests: list[dict[str, str]] = []

    for record in records:
        sample_id = str(record["sample_id"])
        partition = str(record.get("partition", ""))
        function_blob = record.get("function")
        if not isinstance(function_blob, dict):
            raise ValueError(f"sample {sample_id}: missing function object")
        audit_sample_id = _opaque_id(
            alias_secret,
            "local-variable-semantic-audit-sample-v2",
            sample_id,
            prefix="as_",
            length=20,
        )
        source_status = record.get("source_status")
        if source_status not in {"ok", "error"}:
            raise ValueError(f"sample {sample_id}: unknown source status {source_status!r}")
        source_status_counts[str(source_status)] += 1
        record_decompilers = record.get("decompilers")
        if not isinstance(record_decompilers, dict):
            raise ValueError(f"sample {sample_id}: missing decompiler entries")
        if source_status != "ok":
            statuses: dict[str, str] = {}
            for backend_id in selected_backends:
                entry = record_decompilers[backend_id]
                if not isinstance(entry, dict) or entry.get("status") != "source_error":
                    raise ValueError(
                        f"sample {sample_id}/{backend_id}: source error status mismatch"
                    )
                statuses[backend_id] = "source_error"
                backend_function_status[backend_id]["source_error"] += 1
                backend_function_status_by_partition[backend_id][partition]["source_error"] += 1
            skipped_source_records.append(
                {
                    "audit_sample_id": audit_sample_id,
                    "partition": partition,
                    "source_status": str(source_status),
                    "backend_statuses": statuses,
                }
            )
            continue

        source_blob = record.get("source_evidence")
        if not isinstance(source_blob, dict) or not isinstance(source_blob.get("variables"), list):
            raise ValueError(f"sample {sample_id}: missing source evidence")
        scorer_source_variables = [
            variable for variable in source_blob["variables"] if isinstance(variable, dict)
        ]
        scorer_source_ids = [variable.get("identity") for variable in scorer_source_variables]
        if any(not isinstance(identity, str) or not identity for identity in scorer_source_ids):
            raise ValueError(f"sample {sample_id}: invalid source evidence identity")
        if len(scorer_source_ids) != len(set(scorer_source_ids)):
            raise ValueError(f"sample {sample_id}: duplicate source evidence identity")
        observable_blinded = [
            variable for variable in scorer_source_variables if _observable(variable)
        ]
        observable_source_ids = {str(variable["identity"]) for variable in observable_blinded}

        address = _parse_address(
            function_blob.get("address"),
            field="function address",
        )
        optimization = str(function_blob.get("optimization", ""))
        binary_name = str(function_blob.get("binary", ""))
        function_name = str(function_blob.get("name", ""))
        project = str(function_blob.get("project", ""))
        function_public = {
            "project": project,
            "optimization": optimization,
            "binary": binary_name,
            "name": function_name,
        }
        binary_path = _resolve_artifact(record, "binary", scorer_path)
        source_path = _resolve_artifact(record, "source", scorer_path)
        preprocessed_path = _resolve_artifact(record, "preprocessed", scorer_path)
        stripped_path = _resolve_artifact(record, "stripped_input", scorer_path)
        artifact_digests.append(
            {
                "audit_sample_id": audit_sample_id,
                "binary_sha256": _file_sha256(binary_path),
                "source_sha256": _file_sha256(source_path),
                "preprocessed_sha256": _file_sha256(preprocessed_path),
                "stripped_input_sha256": _file_sha256(stripped_path),
            }
        )
        source_lines = load_source_lines(source_path, preprocessed_path)
        source = extract_source_evidence(
            binary_path,
            source_path,
            function_name,
            preprocessed_path=preprocessed_path,
            include_inlined=include_inlined,
            function_address=address,
            source_lines=source_lines,
        )
        source_by_id = {variable.identity: variable for variable in source.variables}
        if len(source_by_id) != len(source.variables):
            raise ValueError(f"sample {sample_id}: duplicate reconstructed source identity")
        if set(scorer_source_ids) != set(source_by_id):
            raise ValueError(f"sample {sample_id}: scorer/checkpoint source identity sets differ")
        if not observable_source_ids <= set(source_by_id):
            raise ValueError(f"sample {sample_id}: observable source rejoin failed")
        _require_same_non_name_evidence(
            source_blob,
            source.to_dict(),
            f"sample {sample_id}: source",
        )
        from decbench.experimental.local_variable_checkpoint import (
            _function_instruction_set,
        )

        instruction_addresses = _function_instruction_set(
            binary_path,
            source.start,
            source.end,
        )
        type_candidates = _source_type_candidates(
            binary_path,
            function_name,
            address,
        )
        artifacts = record.get("artifacts", {})
        declaration_file = str(artifacts.get("dwarf_decl_file") or source_path.name)
        declaration_line = artifacts.get("dwarf_decl_line")
        source_code = _source_function_code(
            source_path,
            preprocessed_path,
            function_name,
            int(declaration_line) if isinstance(declaration_line, int) else None,
        )
        source_audit_ids = {
            source_id: _opaque_id(
                alias_secret,
                "local-variable-semantic-audit-source-v2",
                sample_id,
                source_id,
                prefix="sv_",
                length=16,
            )
            for source_id in sorted(observable_source_ids)
        }
        public_source_variables = [
            _source_public_variable(
                source_by_id[source_id],
                source_audit_id=source_audit_ids[source_id],
                type_candidates=type_candidates,
                source_lines=source_lines,
                declaration_file=declaration_file,
                context_lines=context_lines,
            )
            for source_id in sorted(observable_source_ids)
        ]
        if not observable_source_ids:
            zero_observable_records.append(
                {
                    "audit_sample_id": audit_sample_id,
                    "partition": partition,
                    "function": function_public,
                }
            )

        for backend_id in selected_backends:
            scorer_entry = record_decompilers[backend_id]
            if not isinstance(scorer_entry, dict):
                raise ValueError(f"sample {sample_id}/{backend_id}: invalid backend entry")
            status = str(scorer_entry.get("status"))
            if status not in BACKEND_STATUSES:
                raise ValueError(f"sample {sample_id}/{backend_id}: unknown status {status!r}")
            backend_function_status[backend_id][status] += 1
            backend_function_status_by_partition[backend_id][partition][status] += 1
            checkpoint_entry = checkpoint.find_exact(
                optimization=optimization,
                binary=binary_name,
                address=address,
                name=function_name,
                backend_id=backend_id,
            )
            decompiled: DecompiledAuditEvidence | None = None
            if checkpoint_entry is not None:
                decompiled = _decompiled_audit_evidence(
                    checkpoint_entry.function,
                    checkpoint_entry.result,
                    backend_id=backend_id,
                    function_name=function_name,
                    function_end=source.end,
                    audit_sample_id=audit_sample_id,
                    alias_secret=alias_secret,
                    audit_seed=audit_seed,
                    instruction_addresses=instruction_addresses,
                    context_lines=context_lines,
                    scorer_status=status,
                )
            accepted = _validate_scorer_backend(
                sample_id=sample_id,
                backend_id=backend_id,
                scorer_entry=scorer_entry,
                checkpoint_entry=checkpoint_entry,
                observable_source_ids=observable_source_ids,
                decompiled=decompiled,
            )
            if decompiled is None:
                decompiled = _missing_decompiled_evidence(backend_id, status)
            if not observable_source_ids:
                continue

            evidence_id = _opaque_id(
                alias_secret,
                "local-variable-semantic-audit-evidence-v2",
                sample_id,
                backend_id,
                prefix="ev_",
                length=24,
            )
            evidence_payload = {
                "schema_version": SCHEMA_VERSION,
                "kind": EVIDENCE_KIND,
                "evidence_id": evidence_id,
                "audit_sample_id": audit_sample_id,
                "backend_id": backend_id,
                "function": function_public,
                "source_function_code": source_code,
                "source_variables": public_source_variables,
                "decompiled": decompiled.public,
                "review_question": (
                    "For every source variable, select all anonymized decompiler "
                    "variables carrying its semantic value, or mark none/unknown."
                ),
            }
            evidence_hash = evidence_sha256(evidence_payload)
            evidence_row = {
                **evidence_payload,
                "evidence_sha256": evidence_hash,
            }
            validate_public_evidence(evidence_row)
            evidence_rows.append(evidence_row)

            accepted_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for match in accepted:
                accepted_by_source[str(match["source_id"])].append(match)
            for source_id in sorted(observable_source_ids):
                case_id = _opaque_id(
                    alias_secret,
                    "local-variable-semantic-audit-case-v2",
                    sample_id,
                    backend_id,
                    source_id,
                    prefix="case_",
                    length=24,
                )
                provisional_cases.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "kind": CASE_KIND,
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "evidence_sha256": evidence_hash,
                        "audit_sample_id": audit_sample_id,
                        "backend_id": backend_id,
                        "source_variable_audit_id": source_audit_ids[source_id],
                    }
                )
                normalized_matches: list[dict[str, Any]] = []
                for match in accepted_by_source.get(source_id, []):
                    decompiled_id = str(match["decompiled_id"])
                    alias = decompiled.id_to_alias.get(decompiled_id)
                    if alias is None:
                        raise ValueError(
                            f"sample {sample_id}/{backend_id}: accepted target "
                            f"{decompiled_id} has no checkpoint alias"
                        )
                    normalized_matches.append(
                        {
                            "decompiled_id": decompiled_id,
                            "decompiled_audit_id": alias,
                            "stage": match.get("stage"),
                            "score": match.get("score"),
                            "confidence": match.get("confidence"),
                        }
                    )
                version = (
                    checkpoint_entry.result.decompiler.decompiler_version
                    if checkpoint_entry is not None
                    else None
                )
                provisional_private[case_id] = {
                    "schema_version": SCHEMA_VERSION,
                    "kind": PRIVATE_KIND,
                    "case_id": case_id,
                    "sample_id": sample_id,
                    "audit_sample_id": audit_sample_id,
                    "partition": partition,
                    "function": {**function_public, "address": f"0x{address:x}"},
                    "backend_id": backend_id,
                    "backend_version": (str(version) if version is not None else None),
                    "backend_status": status,
                    "source_id": source_id,
                    "source_audit_id": source_audit_ids[source_id],
                    "decompiled_audit_map": {
                        alias: list(identities)
                        for alias, identities in sorted(decompiled.alias_to_ids.items())
                    },
                    "checkpoint_decompiled_ids": sorted(decompiled.id_to_alias),
                    "matcher_accepted": normalized_matches,
                }
                backend_case_status[backend_id][status] += 1

    evidence_rows.sort(
        key=lambda row: stable_hash(
            "local-variable-semantic-audit-evidence-order-v2",
            row["evidence_id"],
        )
    )
    assignment = _assign_shards(evidence_rows, provisional_cases, shard_count)
    cases: list[dict[str, Any]] = []
    private_rows: list[dict[str, Any]] = []
    for provisional in provisional_cases:
        payload = {
            **provisional,
            "shard_id": assignment[str(provisional["evidence_id"])],
        }
        case_hash = evidence_sha256(payload)
        case = {**payload, "case_sha256": case_hash}
        validate_public_case(case)
        cases.append(case)
        private = provisional_private[str(case["case_id"])]
        private_rows.append(
            {
                **private,
                "case_sha256": case_hash,
                "evidence_id": case["evidence_id"],
                "evidence_sha256": case["evidence_sha256"],
                "shard_id": case["shard_id"],
            }
        )
    cases.sort(
        key=lambda row: stable_hash(
            "local-variable-semantic-audit-case-order-v2",
            row["case_id"],
        )
    )
    private_by_id = {str(row["case_id"]): row for row in private_rows}
    if len(private_by_id) != len(private_rows):
        raise ValueError("private join contains duplicate case IDs during build")
    private_rows = [private_by_id[str(case["case_id"])] for case in cases]
    templates = [_label_template(case) for case in cases]

    output_dir.mkdir(parents=True, exist_ok=True)
    label_path = output_dir / LABEL_FILENAME
    if label_path.exists():
        existing = read_jsonl(label_path)
        validate_labels(
            existing,
            cases,
            evidence_rows,
            require_complete=False,
        )
        label_status = "preserved"
    else:
        write_jsonl(label_path, templates)
        label_status = "created"

    evidence_path = output_dir / EVIDENCE_FILENAME
    case_path = output_dir / CASE_FILENAME
    private_path = output_dir / PRIVATE_JOIN_FILENAME
    write_jsonl(evidence_path, evidence_rows)
    write_jsonl(case_path, cases)
    write_jsonl(private_path, private_rows, private=True)
    shard_manifest, shard_paths = _write_reviewer_shards(
        output_dir,
        evidence_rows,
        cases,
        templates,
    )

    if not isinstance(aggregate_provenance, dict):
        raise ValueError("aggregate provenance disappeared after validation")
    coverage = {
        "selected_scorer_function_count": len(records),
        "source_status_function_counts": dict(sorted(source_status_counts.items())),
        "backend_function_status_counts": {
            backend: dict(sorted(counts.items()))
            for backend, counts in sorted(backend_function_status.items())
        },
        "backend_function_status_counts_by_partition": {
            backend: {
                partition_name: dict(sorted(counts.items()))
                for partition_name, counts in sorted(partitions.items())
            }
            for backend, partitions in sorted(backend_function_status_by_partition.items())
        },
        "backend_case_status_counts": {
            backend: dict(sorted(counts.items()))
            for backend, counts in sorted(backend_case_status.items())
        },
        "source_skipped_count": len(skipped_source_records),
        "source_skipped": skipped_source_records,
        "zero_observable_function_count": len(zero_observable_records),
        "zero_observable_functions": zero_observable_records,
    }
    immutable_paths = [
        alias_secret_path,
        evidence_path,
        case_path,
        private_path,
        *shard_paths,
    ]
    file_digests = {
        str(path.relative_to(output_dir)): _file_sha256(path) for path in immutable_paths
    }
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": PACKAGE_KIND,
        "evidence_count": len(evidence_rows),
        "case_count": len(cases),
        "source_function_count": len({str(row["audit_sample_id"]) for row in evidence_rows}),
        "selected_backends": selected_backends,
        "coverage": coverage,
        "frozen_bins": {
            "version": FROZEN_BIN_VERSION,
            "score_boundaries": list(FROZEN_SCORE_BOUNDS),
            "minimum_runner_up_gap_boundaries": list(FROZEN_MINIMUM_GAP_BOUNDS),
        },
        "audit_seed_sha256": hashlib.sha256(audit_seed.encode()).hexdigest(),
        "alias_secret_commitment_sha256": _alias_secret_commitment(alias_secret),
        "artifact_digests": sorted(
            artifact_digests,
            key=lambda row: str(row["audit_sample_id"]),
        ),
        "input_provenance": {
            **aggregate_provenance,
            "validated": validated_provenance,
        },
        "file_digests": dict(sorted(file_digests.items())),
        "label_template_status": label_status,
        "shard_manifest_payload_sha256": shard_manifest["manifest_payload_sha256"],
        "review_protocol": {
            "unit": "one observable source variable x one exact backend key",
            "relation_group": "one source function x backend stays in one shard",
            "oracle_statuses": sorted(ORACLE_STATUSES),
            "private_join_is_not_an_auditor_input": True,
            "coverage_only_strata": (
                "source-error and zero-observable functions contribute to "
                "coverage tables only because no source-variable oracle case exists"
            ),
            "anonymization_scope": (
                "non-member C identifier tokens are replaced; strings, comments, "
                "and member-field spellings are preserved because they are not "
                "local-variable identifiers"
            ),
        },
        "public_structured_omissions": sorted(FORBIDDEN_PUBLIC_KEYS),
    }
    manifest = {
        **manifest_payload,
        "manifest_payload_sha256": evidence_sha256(manifest_payload),
    }
    write_json(output_dir / MANIFEST_FILENAME, manifest)
    return manifest


def _safe_package_path(package_dir: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"manifest contains unsafe file path {relative!r}")
    resolved_root = package_dir.resolve()
    resolved = (package_dir / path).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"manifest file escapes package: {relative!r}")
    return resolved


def _validate_manifest(package_dir: Path) -> dict[str, Any]:
    manifest = _read_json(package_dir / MANIFEST_FILENAME)
    _require_schema(manifest, PACKAGE_KIND, "package manifest")
    _require_exact_keys(
        manifest,
        {
            "schema_version",
            "kind",
            "evidence_count",
            "case_count",
            "source_function_count",
            "selected_backends",
            "coverage",
            "frozen_bins",
            "audit_seed_sha256",
            "alias_secret_commitment_sha256",
            "artifact_digests",
            "input_provenance",
            "file_digests",
            "label_template_status",
            "shard_manifest_payload_sha256",
            "review_protocol",
            "public_structured_omissions",
            "manifest_payload_sha256",
        },
        "package manifest",
    )
    payload = dict(manifest)
    claimed = payload.pop("manifest_payload_sha256", None)
    if not isinstance(claimed, str) or evidence_sha256(payload) != claimed:
        raise ValueError("package manifest payload SHA-256 mismatch")
    bins = manifest.get("frozen_bins")
    expected_bins = {
        "version": FROZEN_BIN_VERSION,
        "score_boundaries": list(FROZEN_SCORE_BOUNDS),
        "minimum_runner_up_gap_boundaries": list(FROZEN_MINIMUM_GAP_BOUNDS),
    }
    if bins != expected_bins:
        raise ValueError("package frozen score/gap bins are unsupported or changed")
    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("package coverage object is invalid")
    _require_exact_keys(
        coverage,
        {
            "selected_scorer_function_count",
            "source_status_function_counts",
            "backend_function_status_counts",
            "backend_function_status_counts_by_partition",
            "backend_case_status_counts",
            "source_skipped_count",
            "source_skipped",
            "zero_observable_function_count",
            "zero_observable_functions",
        },
        "package coverage",
    )
    for index, skipped in enumerate(coverage.get("source_skipped", [])):
        if not isinstance(skipped, dict):
            raise ValueError(f"package coverage.source_skipped[{index}] is invalid")
        _require_exact_keys(
            skipped,
            {"audit_sample_id", "partition", "source_status", "backend_statuses"},
            f"package coverage.source_skipped[{index}]",
        )
    for index, zero in enumerate(coverage.get("zero_observable_functions", [])):
        if not isinstance(zero, dict):
            raise ValueError(f"package coverage.zero_observable_functions[{index}] is invalid")
        _require_exact_keys(
            zero,
            {"audit_sample_id", "partition", "function"},
            f"package coverage.zero_observable_functions[{index}]",
        )
        function = zero.get("function")
        if not isinstance(function, dict):
            raise ValueError(
                f"package coverage.zero_observable_functions[{index}].function is invalid"
            )
        _require_exact_keys(
            function,
            {"project", "optimization", "binary", "name"},
            f"package coverage.zero_observable_functions[{index}].function",
        )
    artifact_digests = manifest.get("artifact_digests")
    if not isinstance(artifact_digests, list):
        raise ValueError("package artifact digests are invalid")
    artifact_ids: set[str] = set()
    for index, artifact in enumerate(artifact_digests):
        if not isinstance(artifact, dict):
            raise ValueError(f"package artifact_digests[{index}] is invalid")
        _require_exact_keys(
            artifact,
            {
                "audit_sample_id",
                "binary_sha256",
                "source_sha256",
                "preprocessed_sha256",
                "stripped_input_sha256",
            },
            f"package artifact_digests[{index}]",
        )
        sample = _require_string(
            artifact["audit_sample_id"],
            f"package artifact_digests[{index}].audit_sample_id",
        )
        if sample in artifact_ids:
            raise ValueError("package artifact digests contain duplicate source functions")
        artifact_ids.add(sample)
        for field in (
            "binary_sha256",
            "source_sha256",
            "preprocessed_sha256",
            "stripped_input_sha256",
        ):
            if not isinstance(artifact[field], str) or not re.fullmatch(
                r"[0-9a-f]{64}", artifact[field]
            ):
                raise ValueError(f"package artifact_digests[{index}].{field} is invalid")
    expected_protocol = {
        "unit": "one observable source variable x one exact backend key",
        "relation_group": "one source function x backend stays in one shard",
        "oracle_statuses": sorted(ORACLE_STATUSES),
        "private_join_is_not_an_auditor_input": True,
        "coverage_only_strata": (
            "source-error and zero-observable functions contribute to coverage "
            "tables only because no source-variable oracle case exists"
        ),
        "anonymization_scope": (
            "non-member C identifier tokens are replaced; strings, comments, "
            "and member-field spellings are preserved because they are not "
            "local-variable identifiers"
        ),
    }
    if manifest.get("review_protocol") != expected_protocol:
        raise ValueError("package review protocol is unsupported or changed")
    if manifest.get("public_structured_omissions") != sorted(FORBIDDEN_PUBLIC_KEYS):
        raise ValueError("package public omission policy is unsupported or changed")
    if manifest.get("label_template_status") not in {"created", "preserved"}:
        raise ValueError("package label-template status is invalid")
    alias_secret, _alias_secret_path = _read_alias_secret(package_dir)
    commitment = manifest.get("alias_secret_commitment_sha256")
    if not isinstance(commitment, str) or not hmac.compare_digest(
        commitment,
        _alias_secret_commitment(alias_secret),
    ):
        raise ValueError("package manifest/alias-secret commitment mismatch")
    provenance = manifest.get("input_provenance")
    required_provenance = {
        "hash_algorithm",
        "checkpoint_sha256",
        "score_config",
        "score_config_sha256",
        "strict_universe",
        "selected_sample_sha256",
        "selected_sample_count",
        "decompilers",
        "run_binding_version",
        "run_binding_sha256",
        "scorer_jsonl_serialization",
        "scorer_jsonl_sha256",
        "validated",
    }
    if not isinstance(provenance, dict) or set(provenance) != required_provenance:
        raise ValueError("package manifest lacks complete scorer provenance")
    if provenance.get("hash_algorithm") != "sha256":
        raise ValueError("package provenance uses an unsupported hash algorithm")
    strict_universe = provenance.get("strict_universe")
    if not isinstance(strict_universe, dict):
        raise ValueError("package strict-universe provenance is invalid")
    _require_exact_keys(
        strict_universe,
        {"version", "member_count", "sha256"},
        "package strict-universe provenance",
    )
    score_config = provenance.get("score_config")
    if not isinstance(score_config, dict):
        raise ValueError("package score-config provenance is invalid")
    _require_exact_keys(
        score_config,
        {
            "version",
            "project",
            "optimizations",
            "decompiler_bases",
            "sample_size",
            "sample_seed",
            "tuning_fraction",
            "include_inlined",
            "min_overlap",
            "ambiguity_margin",
            "bootstrap_iterations",
        },
        "package score-config provenance",
    )
    if provenance.get("decompilers") != manifest.get("selected_backends"):
        # A package can intentionally select a subset, so require an ordered
        # subsequence rather than equality in that case.
        available = provenance.get("decompilers")
        selected = manifest.get("selected_backends")
        if not isinstance(available, list) or not isinstance(selected, list):
            raise ValueError("package backend provenance is invalid")
        if any(backend not in available for backend in selected):
            raise ValueError("package selected backends are not provenance-bound")
    validated = provenance.get("validated")
    if isinstance(validated, dict):
        _require_exact_keys(
            validated,
            {
                "checkpoint_sha256",
                "scorer_jsonl_sha256",
                "run_binding_sha256",
            },
            "package validated provenance",
        )
    if not isinstance(validated, dict) or any(
        validated.get(field) != provenance.get(field)
        for field in (
            "checkpoint_sha256",
            "scorer_jsonl_sha256",
            "run_binding_sha256",
        )
    ):
        raise ValueError("package validated provenance summary is inconsistent")

    digests = manifest.get("file_digests")
    if not isinstance(digests, dict):
        raise ValueError("package manifest has no immutable file digests")
    mandatory = {
        ALIAS_SECRET_FILENAME,
        EVIDENCE_FILENAME,
        CASE_FILENAME,
        PRIVATE_JOIN_FILENAME,
        f"{SHARD_DIRNAME}/{SHARD_MANIFEST_FILENAME}",
    }
    if not mandatory <= set(digests):
        raise ValueError("package manifest omits mandatory immutable file digests")
    for relative, expected in digests.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("package manifest has invalid file digest entry")
        path = _safe_package_path(package_dir, relative)
        if not path.is_file() or _file_sha256(path) != expected:
            raise ValueError(f"package file digest mismatch: {relative}")
    return manifest


def _validate_shards(
    package_dir: Path,
    manifest: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    shard_manifest = _read_json(package_dir / SHARD_DIRNAME / SHARD_MANIFEST_FILENAME)
    _require_schema(
        shard_manifest,
        SHARD_MANIFEST_KIND,
        "reviewer shard manifest",
    )
    _require_exact_keys(
        shard_manifest,
        {
            "schema_version",
            "kind",
            "shard_count",
            "evidence_count",
            "case_count",
            "shards",
            "manifest_payload_sha256",
        },
        "reviewer shard manifest",
    )
    payload = dict(shard_manifest)
    claimed = payload.pop("manifest_payload_sha256", None)
    if not isinstance(claimed, str) or evidence_sha256(payload) != claimed:
        raise ValueError("reviewer shard manifest payload SHA-256 mismatch")
    if claimed != manifest.get("shard_manifest_payload_sha256"):
        raise ValueError("package/shard manifest binding mismatch")
    if shard_manifest.get("evidence_count") != len(evidence_rows):
        raise ValueError("reviewer shard evidence count mismatch")
    if shard_manifest.get("case_count") != len(cases):
        raise ValueError("reviewer shard case count mismatch")
    entries = shard_manifest.get("shards")
    if not isinstance(entries, list):
        raise ValueError("reviewer shard manifest has no shard list")
    evidence_by_id = {str(evidence["evidence_id"]): dict(evidence) for evidence in evidence_rows}
    case_by_id = {str(case["case_id"]): dict(case) for case in cases}
    seen_shards: set[str] = set()
    seen_evidence: set[str] = set()
    seen_cases: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("reviewer shard manifest entry is invalid")
        _require_exact_keys(
            entry,
            {
                "shard_id",
                "file",
                "evidence_ids",
                "case_ids",
                "public_payload_sha256",
                "initial_file_sha256",
            },
            "reviewer shard manifest entry",
        )
        shard_id = entry.get("shard_id")
        filename = entry.get("file")
        if not isinstance(shard_id, str) or shard_id in seen_shards:
            raise ValueError(f"duplicate/invalid reviewer shard ID {shard_id!r}")
        if filename != f"{shard_id}.json":
            raise ValueError(f"reviewer shard {shard_id}: filename mismatch")
        seen_shards.add(shard_id)
        evidence_ids = entry.get("evidence_ids")
        case_ids = entry.get("case_ids")
        if not isinstance(evidence_ids, list) or not isinstance(case_ids, list):
            raise ValueError(f"reviewer shard {shard_id}: invalid coverage lists")
        if set(evidence_ids) & seen_evidence or set(case_ids) & seen_cases:
            raise ValueError(f"reviewer shard {shard_id}: overlapping coverage")
        seen_evidence.update(str(value) for value in evidence_ids)
        seen_cases.update(str(value) for value in case_ids)
        if not set(evidence_ids) <= set(evidence_by_id) or not set(case_ids) <= set(case_by_id):
            raise ValueError(f"reviewer shard {shard_id}: unknown coverage ID")
        shard = _read_json(package_dir / SHARD_DIRNAME / str(filename))
        _validate_reviewer_shard_schema(shard, f"reviewer shard {shard_id}")
        shard_path = package_dir / SHARD_DIRNAME / str(filename)
        if entry.get("initial_file_sha256") != _file_sha256(shard_path):
            raise ValueError(f"reviewer shard {shard_id}: initial file digest mismatch")
        if shard.get("shard_id") != shard_id:
            raise ValueError(f"reviewer shard {shard_id}: ID mismatch")
        immutable = _shard_public_payload(
            shard_id,
            shard.get("evidence", []),
            shard.get("cases", []),
        )
        immutable_hash = evidence_sha256(immutable)
        if immutable_hash != shard.get("public_payload_sha256") or immutable_hash != entry.get(
            "public_payload_sha256"
        ):
            raise ValueError(f"reviewer shard {shard_id}: stale public payload")
        expected_evidence = [evidence_by_id[str(value)] for value in evidence_ids]
        expected_cases = [case_by_id[str(value)] for value in case_ids]
        if shard.get("evidence") != expected_evidence or shard.get("cases") != expected_cases:
            raise ValueError(f"reviewer shard {shard_id}: public evidence differs")
        if any(case.get("shard_id") != shard_id for case in expected_cases):
            raise ValueError(f"reviewer shard {shard_id}: split relation assignment")
        labels = shard.get("labels")
        if not isinstance(labels, list):
            raise ValueError(f"reviewer shard {shard_id}: labels are missing")
        validate_labels(
            labels,
            cases,
            evidence_rows,
            require_complete=False,
            expected_case_ids=set(str(value) for value in case_ids),
        )
    if seen_evidence != set(evidence_by_id) or seen_cases != set(case_by_id):
        raise ValueError("reviewer shard coverage is incomplete")
    if shard_manifest.get("shard_count") != len(seen_shards):
        raise ValueError("reviewer shard count mismatch")
    expected_digest_files = {
        ALIAS_SECRET_FILENAME,
        EVIDENCE_FILENAME,
        CASE_FILENAME,
        PRIVATE_JOIN_FILENAME,
        f"{SHARD_DIRNAME}/{SHARD_MANIFEST_FILENAME}",
        *{
            f"{SHARD_DIRNAME}/{entry['file']}"
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("file"), str)
        },
    }
    if set(manifest.get("file_digests", {})) != expected_digest_files:
        raise ValueError("package manifest immutable file set is incomplete or excessive")
    return shard_manifest


def _load_package(
    package_dir: Path,
    labels_path: Path | None,
    *,
    require_complete: bool,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    manifest = _validate_manifest(package_dir)
    alias_secret, _alias_secret_path = _read_alias_secret(package_dir)
    evidence_rows = read_jsonl(package_dir / EVIDENCE_FILENAME)
    cases = read_jsonl(package_dir / CASE_FILENAME)
    private_rows = read_jsonl(package_dir / PRIVATE_JOIN_FILENAME)
    for evidence in evidence_rows:
        validate_public_evidence(evidence)
    for case in cases:
        validate_public_case(case)
    if manifest.get("evidence_count") != len(evidence_rows):
        raise ValueError("package evidence count differs from manifest")
    if manifest.get("case_count") != len(cases):
        raise ValueError("package case count differs from manifest")
    selected_backends = manifest.get("selected_backends")
    if not isinstance(selected_backends, list) or len(selected_backends) != len(
        set(selected_backends)
    ):
        raise ValueError("package selected backend list is invalid")
    observed_source_functions = {str(evidence["audit_sample_id"]) for evidence in evidence_rows}
    if manifest.get("source_function_count") != len(observed_source_functions):
        raise ValueError("package source-function count differs from manifest")
    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("package coverage object is missing")
    selected_count = coverage.get("selected_scorer_function_count")
    provenance = manifest.get("input_provenance", {})
    if selected_count != provenance.get("selected_sample_count"):
        raise ValueError("package scorer function count/provenance mismatch")
    source_status_counts = coverage.get("source_status_function_counts")
    if (
        not isinstance(source_status_counts, dict)
        or not set(source_status_counts) <= {"ok", "error"}
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in source_status_counts.values()
        )
        or sum(int(value) for value in source_status_counts.values()) != selected_count
    ):
        raise ValueError("package source status counts are inconsistent")
    skipped = coverage.get("source_skipped")
    zero_observable = coverage.get("zero_observable_functions")
    if (
        not isinstance(skipped, list)
        or coverage.get("source_skipped_count") != len(skipped)
        or not isinstance(zero_observable, list)
        or coverage.get("zero_observable_function_count") != len(zero_observable)
    ):
        raise ValueError("package source skip/zero-observable counts are inconsistent")
    expected_observed = int(source_status_counts.get("ok", 0)) - len(zero_observable)
    if expected_observed != len(observed_source_functions):
        raise ValueError("package observable source-function coverage is inconsistent")
    if len(evidence_rows) != expected_observed * len(selected_backends):
        raise ValueError("package evidence groups do not cover every selected backend")
    artifact_digests = manifest.get("artifact_digests", [])
    source_ok_count = int(source_status_counts.get("ok", 0))
    if len(artifact_digests) != source_ok_count:
        raise ValueError("package audit-time artifact digest coverage is incomplete")
    artifact_ids = {str(row.get("audit_sample_id")) for row in artifact_digests}
    zero_ids = {str(row.get("audit_sample_id")) for row in zero_observable}
    if artifact_ids != observed_source_functions | zero_ids:
        raise ValueError("package audit-time artifact digests name the wrong functions")

    evidence_by_id: dict[str, dict[str, Any]] = {}
    evidence_groups: set[tuple[str, str]] = set()
    for evidence in evidence_rows:
        evidence_id = str(evidence.get("evidence_id", ""))
        if evidence_id in evidence_by_id:
            raise ValueError(f"duplicate evidence_id {evidence_id}")
        evidence_by_id[evidence_id] = evidence
        backend_id = evidence.get("backend_id")
        if backend_id not in selected_backends:
            raise ValueError(f"evidence {evidence_id}: unknown exact backend key")
        group = (str(evidence.get("audit_sample_id")), str(backend_id))
        if group in evidence_groups:
            raise ValueError(f"duplicate public evidence relation group {group}")
        evidence_groups.add(group)
        source_variables = evidence.get("source_variables")
        if not isinstance(source_variables, list):
            raise ValueError(f"evidence {evidence_id}: source variables are missing")
        source_ids = [
            variable.get("audit_id") for variable in source_variables if isinstance(variable, dict)
        ]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError(f"evidence {evidence_id}: duplicate source audit ID")

    case_by_id: dict[str, dict[str, Any]] = {}
    cases_by_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        case_id = str(case.get("case_id", ""))
        if case_id in case_by_id:
            raise ValueError(f"duplicate case_id {case_id}")
        case_by_id[case_id] = case
        evidence = evidence_by_id.get(str(case.get("evidence_id")))
        if evidence is None:
            raise ValueError(f"case {case_id}: unknown evidence_id")
        if case.get("evidence_sha256") != evidence.get("evidence_sha256"):
            raise ValueError(f"case {case_id}: evidence SHA-256 mismatch")
        source_ids = {
            variable.get("audit_id")
            for variable in evidence.get("source_variables", [])
            if isinstance(variable, dict)
        }
        if case.get("source_variable_audit_id") not in source_ids:
            raise ValueError(f"case {case_id}: unknown source variable audit ID")
        if case.get("backend_id") != evidence.get("backend_id"):
            raise ValueError(f"case {case_id}: backend/evidence mismatch")
        if case.get("audit_sample_id") != evidence.get("audit_sample_id"):
            raise ValueError(f"case {case_id}: source-function/evidence mismatch")
        cases_by_evidence[str(case["evidence_id"])].append(case)
    _validate_evidence_case_coverage(evidence_by_id, cases_by_evidence)

    private_by_id: dict[str, dict[str, Any]] = {}
    private_group_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    private_group_targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    private_group_maps: dict[tuple[str, str], dict[str, Any]] = {}
    private_group_status: dict[tuple[str, str], str] = {}
    for row in private_rows:
        _require_schema(
            row,
            PRIVATE_KIND,
            f"private join {row.get('case_id')}",
        )
        case_id = str(row.get("case_id", ""))
        _require_exact_keys(
            row,
            {
                "schema_version",
                "kind",
                "case_id",
                "case_sha256",
                "evidence_id",
                "evidence_sha256",
                "shard_id",
                "sample_id",
                "audit_sample_id",
                "partition",
                "function",
                "backend_id",
                "backend_version",
                "backend_status",
                "source_id",
                "source_audit_id",
                "decompiled_audit_map",
                "checkpoint_decompiled_ids",
                "matcher_accepted",
            },
            f"private join {case_id}",
        )
        private_function = row.get("function")
        if not isinstance(private_function, dict):
            raise ValueError(f"case {case_id}: private function is invalid")
        _require_exact_keys(
            private_function,
            {"project", "optimization", "binary", "name", "address"},
            f"case {case_id}: private function",
        )
        for field in ("project", "optimization", "binary", "name", "address"):
            _require_string(
                private_function[field],
                f"case {case_id}: private function.{field}",
            )
        if not re.fullmatch(r"0x[0-9a-f]+", private_function["address"]):
            raise ValueError(f"case {case_id}: private function address is invalid")
        if row.get("backend_version") is not None:
            _require_string(
                row.get("backend_version"),
                f"case {case_id}: backend_version",
            )
        _require_string(row.get("partition"), f"case {case_id}: partition", allow_empty=True)
        if case_id in private_by_id:
            raise ValueError(f"private join contains duplicate case_id {case_id}")
        private_by_id[case_id] = row
        case = case_by_id.get(case_id)
        if case is None:
            raise ValueError(f"private join contains unknown case_id {case_id}")
        for field in (
            "case_sha256",
            "evidence_id",
            "evidence_sha256",
            "shard_id",
            "audit_sample_id",
            "backend_id",
        ):
            if row.get(field) != case.get(field):
                raise ValueError(f"case {case_id}: private {field} mismatch")
        if row.get("backend_status") not in BACKEND_STATUSES:
            raise ValueError(f"case {case_id}: invalid private backend status")
        evidence = evidence_by_id[str(case["evidence_id"])]
        if {
            field: private_function[field]
            for field in ("project", "optimization", "binary", "name")
        } != evidence.get("function"):
            raise ValueError(f"case {case_id}: private/public function metadata differs")
        if row.get("backend_status") != evidence.get("decompiled", {}).get("status"):
            raise ValueError(f"case {case_id}: private/public backend status mismatch")
        mapping = row.get("decompiled_audit_map")
        checkpoint_ids = row.get("checkpoint_decompiled_ids")
        if not isinstance(mapping, dict) or not isinstance(checkpoint_ids, list):
            raise ValueError(f"case {case_id}: private identity map is invalid")
        public_catalog = evidence.get("decompiled", {}).get("variables")
        if not isinstance(public_catalog, list):
            raise ValueError(f"case {case_id}: public decompiler catalog is invalid")
        public_by_alias = {
            str(variable.get("audit_id")): variable
            for variable in public_catalog
            if isinstance(variable, dict)
        }
        if len(public_by_alias) != len(public_catalog) or set(mapping) != set(public_by_alias):
            raise ValueError(f"case {case_id}: private alias keys differ from public catalog")
        for alias, identities in mapping.items():
            if not isinstance(alias, str) or not isinstance(identities, list) or not identities:
                raise ValueError(f"case {case_id}: private alias group is invalid")
            if any(not isinstance(identity, str) or not identity for identity in identities):
                raise ValueError(f"case {case_id}: private alias identities are invalid")
            catalog = public_by_alias[alias]
            if catalog.get("alias_group_size") != len(identities) or catalog.get(
                "ambiguous_alias"
            ) != (len(identities) != 1):
                raise ValueError(
                    f"case {case_id}: public alias group metadata differs from private map"
                )
        flattened = [
            identity
            for identities in mapping.values()
            if isinstance(identities, list)
            for identity in identities
        ]
        if len(flattened) != len(set(flattened)) or set(flattened) != set(checkpoint_ids):
            raise ValueError(f"case {case_id}: private identity map is not bijective")
        sample_id = _require_string(row.get("sample_id"), f"case {case_id}: sample_id")
        backend_id = _require_string(row.get("backend_id"), f"case {case_id}: backend_id")
        source_id = _require_string(row.get("source_id"), f"case {case_id}: source_id")
        expected_audit_sample_id = _opaque_id(
            alias_secret,
            "local-variable-semantic-audit-sample-v2",
            sample_id,
            prefix="as_",
            length=20,
        )
        if row.get("audit_sample_id") != expected_audit_sample_id:
            raise ValueError(f"case {case_id}: audit sample ID does not verify under package key")
        expected_source_audit_id = _opaque_id(
            alias_secret,
            "local-variable-semantic-audit-source-v2",
            sample_id,
            source_id,
            prefix="sv_",
            length=16,
        )
        if (
            row.get("source_audit_id") != expected_source_audit_id
            or case.get("source_variable_audit_id") != expected_source_audit_id
        ):
            raise ValueError(f"case {case_id}: source audit ID does not verify under package key")
        expected_evidence_id = _opaque_id(
            alias_secret,
            "local-variable-semantic-audit-evidence-v2",
            sample_id,
            backend_id,
            prefix="ev_",
            length=24,
        )
        if row.get("evidence_id") != expected_evidence_id:
            raise ValueError(f"case {case_id}: evidence ID does not verify under package key")
        expected_case_id = _opaque_id(
            alias_secret,
            "local-variable-semantic-audit-case-v2",
            sample_id,
            backend_id,
            source_id,
            prefix="case_",
            length=24,
        )
        if case_id != expected_case_id:
            raise ValueError(f"case {case_id}: case ID does not verify under package key")
        for alias, identities in mapping.items():
            suffix_length = len(alias) - len("dv_")
            if suffix_length < 12 or suffix_length % 2:
                raise ValueError(f"case {case_id}: private alias length is invalid")
            expected_alias = _alias_for_identity_group(
                alias_secret=alias_secret,
                audit_sample_id=expected_audit_sample_id,
                backend_id=backend_id,
                identities=tuple(identities),
                length=suffix_length,
            )
            if alias != expected_alias:
                raise ValueError(
                    f"case {case_id}: decompiler alias does not verify under package key"
                )
        group = (str(row["audit_sample_id"]), str(row["backend_id"]))
        if not source_id or source_id in private_group_sources[group]:
            raise ValueError(f"case {case_id}: duplicate/invalid private source identity")
        private_group_sources[group].add(source_id)
        previous_map = private_group_maps.setdefault(group, dict(mapping))
        if previous_map != mapping:
            raise ValueError(f"case {case_id}: identity map changes within relation group")
        previous_status = private_group_status.setdefault(
            group,
            str(row["backend_status"]),
        )
        if previous_status != row["backend_status"]:
            raise ValueError(f"case {case_id}: status changes within relation group")
        accepted = row.get("matcher_accepted")
        if not isinstance(accepted, list):
            raise ValueError(f"case {case_id}: matcher_accepted is invalid")
        seen_targets: set[str] = set()
        for match in accepted:
            if not isinstance(match, dict):
                raise ValueError(f"case {case_id}: invalid accepted matcher row")
            _require_exact_keys(
                match,
                {
                    "decompiled_id",
                    "decompiled_audit_id",
                    "stage",
                    "score",
                    "confidence",
                },
                f"case {case_id}: accepted matcher row",
            )
            for field in ("decompiled_id", "decompiled_audit_id", "stage"):
                _require_string(match.get(field), f"case {case_id}: matcher {field}")
            score = match.get("score")
            if (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(float(score))
            ):
                raise ValueError(f"case {case_id}: matcher score is invalid")
            confidence = match.get("confidence")
            if not isinstance(confidence, dict):
                raise ValueError(f"case {case_id}: matcher confidence is invalid")
            _require_exact_keys(
                confidence,
                {
                    "source_runner_up_gap",
                    "decompiled_runner_up_gap",
                    "minimum_runner_up_gap",
                },
                f"case {case_id}: matcher confidence",
            )
            if any(
                value is not None
                and (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(float(value))
                )
                for value in confidence.values()
            ):
                raise ValueError(f"case {case_id}: matcher confidence value is invalid")
            target = match.get("decompiled_id")
            alias = match.get("decompiled_audit_id")
            if target not in checkpoint_ids or alias not in mapping or target not in mapping[alias]:
                raise ValueError(f"case {case_id}: accepted target join is stale")
            if target in seen_targets:
                raise ValueError(f"case {case_id}: duplicate accepted target")
            seen_targets.add(str(target))
            if target in private_group_targets[group]:
                raise ValueError(f"case {case_id}: accepted target repeats across relation group")
            private_group_targets[group].add(str(target))
    if set(private_by_id) != set(case_by_id):
        raise ValueError("private join coverage does not match public cases")
    if set(private_group_sources) != evidence_groups:
        raise ValueError("private relation-group coverage differs from public evidence")

    case_status_counts: dict[str, Counter[str]] = {
        str(backend): Counter() for backend in selected_backends
    }
    for case in cases:
        evidence = evidence_by_id[str(case["evidence_id"])]
        case_status_counts[str(case["backend_id"])][str(evidence["decompiled"]["status"])] += 1
    advertised_case_status = coverage.get("backend_case_status_counts")
    if (
        not isinstance(advertised_case_status, dict)
        or set(advertised_case_status) != set(selected_backends)
        or any(
            not isinstance(counts, dict)
            or not set(counts) <= BACKEND_STATUSES
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in counts.values()
            )
            for counts in advertised_case_status.values()
        )
        or any(
            dict(sorted(case_status_counts[backend].items())) != advertised_case_status.get(backend)
            for backend in case_status_counts
        )
    ):
        raise ValueError("package backend case-status counts are inconsistent")
    advertised_function_status = coverage.get("backend_function_status_counts")
    if (
        not isinstance(advertised_function_status, dict)
        or set(advertised_function_status) != set(selected_backends)
        or any(
            not isinstance(advertised_function_status.get(backend), dict)
            or not set(advertised_function_status[backend]) <= BACKEND_STATUSES
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in advertised_function_status[backend].values()
            )
            or sum(int(value) for value in advertised_function_status[backend].values())
            != selected_count
            for backend in selected_backends
        )
    ):
        raise ValueError("package backend function-status counts are inconsistent")
    advertised_by_partition = coverage.get("backend_function_status_counts_by_partition")
    if not isinstance(advertised_by_partition, dict):
        raise ValueError("package backend partition status counts are missing")
    for backend in selected_backends:
        partitions = advertised_by_partition.get(backend)
        if not isinstance(partitions, dict) or any(
            not isinstance(counts, dict) for counts in partitions.values()
        ):
            raise ValueError(f"package backend partition status counts are invalid for {backend}")
        collapsed: Counter[str] = Counter()
        for counts in partitions.values():
            collapsed.update({str(status): int(count) for status, count in counts.items()})
        if dict(sorted(collapsed.items())) != advertised_function_status[backend]:
            raise ValueError(
                f"package backend partition status counts do not collapse for {backend}"
            )

    _validate_shards(package_dir, manifest, evidence_rows, cases)
    label_rows = read_jsonl(labels_path or package_dir / LABEL_FILENAME)
    labels = validate_labels(
        label_rows,
        cases,
        evidence_rows,
        require_complete=require_complete,
    )
    ordered_private = [private_by_id[str(case["case_id"])] for case in cases]
    return manifest, evidence_rows, cases, ordered_private, labels


def validate_audit_package(
    package_dir: Path,
    *,
    labels_path: Path | None = None,
    require_complete: bool = False,
) -> dict[str, Any]:
    manifest, evidence_rows, cases, private_rows, labels = _load_package(
        package_dir,
        labels_path,
        require_complete=require_complete,
    )
    statuses = Counter(
        str(label.get("oracle_status")) if label.get("oracle_status") is not None else "unlabeled"
        for label in labels.values()
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_payload_sha256": manifest["manifest_payload_sha256"],
        "evidence_count": len(evidence_rows),
        "case_count": len(cases),
        "private_join_count": len(private_rows),
        "label_count": len(labels),
        "label_statuses": dict(sorted(statuses.items())),
        "complete": statuses.get("unlabeled", 0) == 0,
    }


def merge_reviewer_labels(
    package_dir: Path,
    shard_label_paths: Sequence[Path],
    *,
    output_path: Path | None = None,
    allow_partial: bool = False,
) -> dict[str, Any]:
    """Merge completed reviewer shards, rejecting stale/conflicting coverage."""

    canonical_labels = package_dir / LABEL_FILENAME
    if allow_partial and (
        output_path is None or output_path.resolve() == canonical_labels.resolve()
    ):
        raise ValueError(
            "a partial merge requires an explicit noncanonical output path; "
            "the package label file must retain full resumable coverage"
        )
    manifest, evidence_rows, cases, _private_rows, _labels = _load_package(
        package_dir,
        None,
        require_complete=False,
    )
    shard_manifest = _read_json(package_dir / SHARD_DIRNAME / SHARD_MANIFEST_FILENAME)
    expected_entries = {str(entry["shard_id"]): entry for entry in shard_manifest["shards"]}
    if not shard_label_paths:
        raise ValueError("at least one completed reviewer shard is required")
    evidence_by_id = {str(evidence["evidence_id"]): evidence for evidence in evidence_rows}
    case_by_id = {str(case["case_id"]): case for case in cases}
    merged: dict[str, dict[str, Any]] = {}
    seen_shards: set[str] = set()
    merge_inputs: list[dict[str, Any]] = []
    for path in shard_label_paths:
        shard = _read_json(path)
        _validate_reviewer_shard_schema(shard, f"reviewer result {path}")
        shard_id = shard.get("shard_id")
        if not isinstance(shard_id, str) or shard_id not in expected_entries:
            raise ValueError(f"{path}: unknown shard_id {shard_id!r}")
        if shard_id in seen_shards:
            raise ValueError(f"{path}: duplicate/conflicting shard {shard_id}")
        seen_shards.add(shard_id)
        expected = expected_entries[shard_id]
        immutable = _shard_public_payload(
            shard_id,
            shard.get("evidence", []),
            shard.get("cases", []),
        )
        immutable_hash = evidence_sha256(immutable)
        if immutable_hash != shard.get("public_payload_sha256") or immutable_hash != expected.get(
            "public_payload_sha256"
        ):
            raise ValueError(f"{path}: stale reviewer evidence payload")
        expected_evidence = [evidence_by_id[str(value)] for value in expected["evidence_ids"]]
        expected_cases = [case_by_id[str(value)] for value in expected["case_ids"]]
        if shard.get("evidence") != expected_evidence or shard.get("cases") != expected_cases:
            raise ValueError(f"{path}: reviewer evidence/cases differ from package")
        assignment = shard.get("reviewer_assignment")
        if not isinstance(assignment, str) or not assignment.strip():
            raise ValueError(f"{path}: reviewer_assignment is required")
        raw_labels = shard.get("labels")
        if not isinstance(raw_labels, list):
            raise ValueError(f"{path}: labels list is missing")
        validated = validate_labels(
            raw_labels,
            cases,
            evidence_rows,
            require_complete=True,
            expected_case_ids=set(str(value) for value in expected["case_ids"]),
            reviewer_assignment=assignment,
        )
        overlap = set(merged) & set(validated)
        if overlap:
            raise ValueError(f"{path}: duplicate/conflicting label cases {sorted(overlap)[:3]}")
        merged.update(validated)
        merge_inputs.append(
            {
                "shard_id": shard_id,
                "reviewer_assignment": assignment,
                "input_file_sha256": _file_sha256(path),
                "public_payload_sha256": immutable_hash,
                "case_count": len(validated),
            }
        )
    expected_shards = set(expected_entries)
    if not allow_partial and seen_shards != expected_shards:
        raise ValueError(
            f"reviewer shard coverage incomplete: missing "
            f"{sorted(expected_shards - seen_shards)}"
        )
    expected_cases = {
        str(case_id)
        for shard_id in seen_shards
        for case_id in expected_entries[shard_id]["case_ids"]
    }
    if set(merged) != expected_cases:
        raise ValueError("merged reviewer labels have incomplete case coverage")
    if not allow_partial and set(merged) != set(case_by_id):
        raise ValueError("final merged labels do not cover the full package")

    ordered_labels = [
        merged[str(case["case_id"])] for case in cases if str(case["case_id"]) in merged
    ]
    destination = output_path or canonical_labels
    write_jsonl(destination, ordered_labels)
    provenance_payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": MERGE_KIND,
        "package_manifest_payload_sha256": manifest["manifest_payload_sha256"],
        "complete": not allow_partial,
        "case_count": len(ordered_labels),
        "label_file": str(destination),
        "label_file_sha256": _file_sha256(destination),
        "inputs": sorted(merge_inputs, key=lambda row: row["shard_id"]),
    }
    provenance = {
        **provenance_payload,
        "merge_payload_sha256": evidence_sha256(provenance_payload),
    }
    provenance_path = (
        destination.with_name(destination.name + ".merge_provenance.json")
        if allow_partial
        else package_dir / MERGE_PROVENANCE_FILENAME
    )
    write_json(provenance_path, provenance)
    return provenance


def _relation_state(
    private_rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
) -> tuple[
    dict[str, set[str]],
    dict[str, bool],
    Counter[tuple[str, str, str]],
]:
    selected_by_case: dict[str, set[str]] = {}
    ambiguous_by_case: dict[str, bool] = {}
    target_degree: Counter[tuple[str, str, str]] = Counter()
    for private in private_rows:
        case_id = str(private["case_id"])
        label = labels[case_id]
        selected: set[str] = set()
        ambiguous = False
        if label.get("oracle_status") == "mapped":
            mapping = private.get("decompiled_audit_map", {})
            if not isinstance(mapping, dict):
                raise ValueError(f"case {case_id}: invalid private alias map")
            for alias in label.get("selected_decompiled_audit_ids", []):
                identities = mapping.get(alias, [])
                if not isinstance(identities, list) or len(identities) != 1:
                    ambiguous = True
                selected.update(str(identity) for identity in identities)
        selected_by_case[case_id] = selected
        ambiguous_by_case[case_id] = ambiguous
        if not ambiguous:
            sample = str(private["audit_sample_id"])
            backend = str(private["backend_id"])
            target_degree.update((sample, backend, identity) for identity in selected)
    return selected_by_case, ambiguous_by_case, target_degree


def _classify_match(
    *,
    label_status: str | None,
    accepted_decompiled_id: str,
    selected: set[str],
    ambiguous_alias: bool,
    target_degree: Mapping[tuple[str, str, str], int],
    audit_sample_id: str,
    backend_id: str,
) -> str:
    if label_status is None:
        return "unlabeled"
    if label_status == "oracle_unknown" or ambiguous_alias:
        return "oracle-unknown"
    if label_status == "none_recovered":
        return "incorrect"
    if accepted_decompiled_id not in selected:
        return "incorrect"
    source_degree = len(selected)
    decompiler_degree = int(
        target_degree.get(
            (audit_sample_id, backend_id, accepted_decompiled_id),
            0,
        )
    )
    if source_degree > 1 and decompiler_degree > 1:
        return "many-to-many"
    if source_degree > 1:
        return "split"
    if decompiler_degree > 1:
        return "merge"
    return "correct"


def _relation_topology(
    *,
    status: str | None,
    selected: set[str],
    ambiguous: bool,
    target_degree: Mapping[tuple[str, str, str], int],
    audit_sample_id: str,
    backend_id: str,
) -> str:
    if status is None:
        return "unlabeled"
    if status == "oracle_unknown" or ambiguous:
        return "oracle-unknown"
    if status == "none_recovered":
        return "none"
    degrees = [
        int(target_degree.get((audit_sample_id, backend_id, identity), 0)) for identity in selected
    ]
    if len(selected) > 1 and any(degree > 1 for degree in degrees):
        return "many-to-many"
    if len(selected) > 1:
        return "split"
    if degrees and degrees[0] > 1:
        return "merge"
    return "one-to-one"


def join_audit_rows(
    evidence_rows: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    private_rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Join completed whole-relation labels to private matcher decisions."""

    evidence_by_id = {str(evidence["evidence_id"]): evidence for evidence in evidence_rows}
    case_by_id = {str(case["case_id"]): case for case in cases}
    selected_by_case, ambiguous_by_case, target_degree = _relation_state(
        private_rows,
        labels,
    )
    joined: list[dict[str, Any]] = []
    for private in private_rows:
        case_id = str(private["case_id"])
        case = case_by_id[case_id]
        evidence = evidence_by_id[str(case["evidence_id"])]
        reviewer_visible_decompiled_ids = {
            str(variable["audit_id"]) for variable in evidence["decompiled"]["variables"]
        }
        if len(reviewer_visible_decompiled_ids) != len(evidence["decompiled"]["variables"]):
            raise ValueError(f"case {case_id}: reviewer-visible decompiler IDs are not unique")
        source_audit_id = str(case["source_variable_audit_id"])
        source_rows = [
            variable
            for variable in evidence["source_variables"]
            if variable.get("audit_id") == source_audit_id
        ]
        if len(source_rows) != 1:
            raise ValueError(f"case {case_id}: source audit ID is not unique in evidence")
        label = labels[case_id]
        status = label.get("oracle_status")
        selected = selected_by_case[case_id]
        ambiguous = ambiguous_by_case[case_id]
        audit_sample_id = str(private["audit_sample_id"])
        backend_id = str(private["backend_id"])
        accepted: list[dict[str, Any]] = []
        accepted_selected = False
        for match in private.get("matcher_accepted", []):
            decompiled_id = str(match["decompiled_id"])
            decompiled_audit_id = str(match["decompiled_audit_id"])
            if decompiled_audit_id not in reviewer_visible_decompiled_ids:
                raise ValueError(
                    f"case {case_id}: matcher target {decompiled_audit_id} is "
                    "not reviewer-visible"
                )
            classification = _classify_match(
                label_status=status,
                accepted_decompiled_id=decompiled_id,
                selected=selected,
                ambiguous_alias=ambiguous,
                target_degree=target_degree,
                audit_sample_id=audit_sample_id,
                backend_id=backend_id,
            )
            accepted_selected = accepted_selected or (
                status == "mapped" and not ambiguous and decompiled_id in selected
            )
            accepted.append(
                {
                    "decompiled_audit_id": decompiled_audit_id,
                    "stage": match.get("stage"),
                    "score": match.get("score"),
                    "confidence": match.get("confidence"),
                    "classification": classification,
                }
            )
        joined.append(
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "case_sha256": case["case_sha256"],
                "evidence_id": case["evidence_id"],
                "evidence_sha256": case["evidence_sha256"],
                "audit_sample_id": audit_sample_id,
                "partition": private.get("partition"),
                "function": evidence["function"],
                "backend_id": backend_id,
                "backend_version": private.get("backend_version"),
                "backend_status": private.get("backend_status"),
                "reviewer_visible_decompiled_variable_count": len(reviewer_visible_decompiled_ids),
                "source_variable": source_rows[0],
                "oracle": {
                    "status": status,
                    "confidence": label.get("confidence"),
                    "reviewer": label.get("reviewer"),
                    "rationale": label.get("rationale"),
                    "selected_decompiled_audit_ids": label.get(
                        "selected_decompiled_audit_ids",
                        [],
                    ),
                    "topology": _relation_topology(
                        status=status,
                        selected=selected,
                        ambiguous=ambiguous,
                        target_degree=target_degree,
                        audit_sample_id=audit_sample_id,
                        backend_id=backend_id,
                    ),
                    "ambiguous_alias_selection": ambiguous,
                },
                "matcher": {
                    "accepted": accepted,
                    "accepted_selected_oracle_neighbor": accepted_selected,
                },
            }
        )
    return joined


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot take a quantile of no values")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _bootstrap_pair_metrics(
    cluster_pairs: Sequence[Mapping[str, tuple[int, int]]],
    *,
    iterations: int,
    seed_parts: Sequence[Any],
) -> dict[str, list[float] | None]:
    metrics = sorted({metric for cluster in cluster_pairs for metric in cluster})
    if iterations <= 0 or not cluster_pairs:
        return {metric: None for metric in metrics}
    rng = random.Random(int(stable_hash("semantic-audit-bootstrap-v2", seed_parts), 16))
    estimates: dict[str, list[float]] = defaultdict(list)
    for _iteration in range(iterations):
        sampled = [rng.choice(cluster_pairs) for _row in cluster_pairs]
        for metric in metrics:
            numerator = sum(row.get(metric, (0, 0))[0] for row in sampled)
            denominator = sum(row.get(metric, (0, 0))[1] for row in sampled)
            if denominator:
                estimates[metric].append(numerator / denominator)
    return {
        metric: (
            [
                _quantile(estimates[metric], 0.025),
                _quantile(estimates[metric], 0.975),
            ]
            if estimates[metric]
            else None
        )
        for metric in metrics
    }


def _edge_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for row in rows:
        for match in row.get("matcher", {}).get("accepted", []):
            confidence = match.get("confidence")
            gap = confidence.get("minimum_runner_up_gap") if isinstance(confidence, dict) else None
            edges.append(
                {
                    "audit_sample_id": str(row["audit_sample_id"]),
                    "backend_id": str(row["backend_id"]),
                    "partition": row.get("partition"),
                    "classification": str(match.get("classification")),
                    "stage": (
                        str(match.get("stage")) if match.get("stage") is not None else "unavailable"
                    ),
                    "score": match.get("score"),
                    "minimum_runner_up_gap": gap,
                }
            )
    return edges


def _edge_pairs(
    edges: Sequence[Mapping[str, Any]],
    parent_edges: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[int, int]]:
    counts = Counter(str(edge["classification"]) for edge in edges)
    correct = counts["correct"]
    incorrect = counts["incorrect"]
    split = counts["split"]
    merge = counts["merge"]
    many = counts["many-to-many"]
    unknown = counts["oracle-unknown"]
    decidable = correct + incorrect + split + merge + many
    labeled = decidable + unknown
    return {
        "valid_edge_precision": (
            correct + split + merge + many,
            decidable,
        ),
        "strict_one_to_one_precision": (correct, decidable),
        "wrong_edge_error_decidable": (incorrect, decidable),
        "wrong_edge_error_lower_bound": (incorrect, labeled),
        "wrong_edge_error_upper_bound": (incorrect + unknown, labeled),
        "oracle_unknown_rate": (unknown, labeled),
        "accepted_contribution": (len(edges), len(parent_edges)),
    }


def _edge_statistics(
    edges: Sequence[Mapping[str, Any]],
    *,
    parent_edges: Sequence[Mapping[str, Any]],
    bootstrap_iterations: int,
    seed_parts: Sequence[Any],
) -> dict[str, Any]:
    counts = Counter(str(edge["classification"]) for edge in edges)
    clusters = sorted({str(edge["audit_sample_id"]) for edge in parent_edges})
    pairs = _edge_pairs(edges, parent_edges)
    cluster_pairs = []
    for cluster in clusters:
        cluster_edges = [edge for edge in edges if edge["audit_sample_id"] == cluster]
        cluster_parent = [edge for edge in parent_edges if edge["audit_sample_id"] == cluster]
        cluster_pairs.append(_edge_pairs(cluster_edges, cluster_parent))
    intervals = _bootstrap_pair_metrics(
        cluster_pairs,
        iterations=bootstrap_iterations,
        seed_parts=seed_parts,
    )
    metrics = {
        metric: {
            "value": _ratio(numerator, denominator),
            "numerator": numerator,
            "denominator": denominator,
            "clustered_bootstrap_ci95": intervals.get(metric),
        }
        for metric, (numerator, denominator) in pairs.items()
    }
    macro_values: list[float] = []
    for cluster in clusters:
        cluster_edges = [edge for edge in edges if edge["audit_sample_id"] == cluster]
        numerator, denominator = _edge_pairs(
            cluster_edges,
            cluster_edges,
        )["valid_edge_precision"]
        if denominator:
            macro_values.append(numerator / denominator)
    return {
        "accepted_count": len(edges),
        "accepted_classifications": {
            classification: counts[classification]
            for classification in sorted(MATCH_CLASSIFICATIONS)
        },
        "metrics": metrics,
        "macro_source_function_valid_edge_precision": (
            sum(macro_values) / len(macro_values) if macro_values else None
        ),
        "accepted_edge_source_function_cluster_count": len(
            {str(edge["audit_sample_id"]) for edge in edges}
        ),
        "contributing_source_function_cluster_count": len(macro_values),
        "total_source_function_cluster_count": len(clusters),
    }


def _bin_label(value: Any, boundaries: Sequence[float]) -> str:
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return "unavailable"
    lower = float("-inf")
    for upper in boundaries:
        if float(value) < upper:
            lower_label = "-inf" if lower == float("-inf") else f"{lower:g}"
            return f"[{lower_label},{upper:g})"
        lower = upper
    return f"[{lower:g},inf)"


def _source_pairs(rows: Sequence[Mapping[str, Any]]) -> dict[str, tuple[int, int]]:
    statuses = Counter(str(row.get("oracle", {}).get("status")) for row in rows)
    mapped_determinate = [
        row
        for row in rows
        if row.get("oracle", {}).get("status") == "mapped"
        and not row.get("oracle", {}).get("ambiguous_alias_selection", False)
    ]
    mapped_accepted = sum(
        bool(
            row.get("matcher", {}).get(
                "accepted_selected_oracle_neighbor",
                False,
            )
        )
        for row in mapped_determinate
    )
    oracle_edge_count = 0
    accepted_oracle_edge_count = 0
    full_relation_count = 0
    for row in mapped_determinate:
        selected = set(
            str(value)
            for value in row.get("oracle", {}).get(
                "selected_decompiled_audit_ids",
                [],
            )
        )
        accepted = {
            str(match.get("decompiled_audit_id"))
            for match in row.get("matcher", {}).get("accepted", [])
            if isinstance(match, Mapping)
        }
        oracle_edge_count += len(selected)
        accepted_oracle_edge_count += len(selected & accepted)
        full_relation_count += accepted == selected
    mapped = statuses["mapped"]
    none = statuses["none_recovered"]
    return {
        "matcher_relation_recall": (
            mapped_accepted,
            len(mapped_determinate),
        ),
        "matcher_oracle_edge_recall": (
            accepted_oracle_edge_count,
            oracle_edge_count,
        ),
        "matcher_full_relation_recall": (
            full_relation_count,
            len(mapped_determinate),
        ),
        "decompiler_source_recovery": (mapped, mapped + none),
        "end_to_end_accepted_recovery": (
            mapped_accepted,
            mapped + none,
        ),
    }


def _source_statistics(
    rows: Sequence[Mapping[str, Any]],
    *,
    bootstrap_iterations: int,
    seed_parts: Sequence[Any],
) -> dict[str, Any]:
    pairs = _source_pairs(rows)
    clusters = sorted({str(row["audit_sample_id"]) for row in rows})
    cluster_pairs = [
        _source_pairs([row for row in rows if str(row["audit_sample_id"]) == cluster])
        for cluster in clusters
    ]
    intervals = _bootstrap_pair_metrics(
        cluster_pairs,
        iterations=bootstrap_iterations,
        seed_parts=seed_parts,
    )
    statuses = Counter(str(row.get("oracle", {}).get("status")) for row in rows)
    topologies = Counter(str(row.get("oracle", {}).get("topology")) for row in rows)
    return {
        "case_count": len(rows),
        "source_function_cluster_count": len(clusters),
        "oracle_statuses": dict(sorted(statuses.items())),
        "topologies": dict(sorted(topologies.items())),
        "metrics": {
            metric: {
                "value": _ratio(numerator, denominator),
                "numerator": numerator,
                "denominator": denominator,
                "clustered_bootstrap_ci95": intervals.get(metric),
            }
            for metric, (numerator, denominator) in pairs.items()
        },
    }


def _candidate_edge_confusion(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    decidable_case_count = 0
    unknown_case_count = 0
    excluded_unknown_pair_count = 0

    for row in rows:
        candidate_count = row.get("reviewer_visible_decompiled_variable_count")
        if (
            not isinstance(candidate_count, int)
            or isinstance(candidate_count, bool)
            or candidate_count < 0
        ):
            raise ValueError(
                f"case {row.get('case_id')}: invalid reviewer-visible " "decompiler-variable count"
            )
        oracle = row.get("oracle", {})
        status = oracle.get("status")
        ambiguous = bool(oracle.get("ambiguous_alias_selection", False))
        if status not in {"mapped", "none_recovered"} or ambiguous:
            unknown_case_count += 1
            excluded_unknown_pair_count += candidate_count
            continue

        decidable_case_count += 1
        selected = {str(value) for value in oracle.get("selected_decompiled_audit_ids", [])}
        accepted = {
            str(match.get("decompiled_audit_id"))
            for match in row.get("matcher", {}).get("accepted", [])
            if isinstance(match, Mapping)
        }
        selected_or_accepted = selected | accepted
        if len(selected_or_accepted) > candidate_count:
            raise ValueError(
                f"case {row.get('case_id')}: selected/accepted edges exceed "
                "the reviewer-visible candidate universe"
            )
        true_positive += len(selected & accepted)
        false_positive += len(accepted - selected)
        false_negative += len(selected - accepted)
        true_negative += candidate_count - len(selected_or_accepted)

    candidate_pair_count = true_positive + false_positive + false_negative + true_negative
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    f1_denominator = 2 * true_positive + false_positive + false_negative
    return {
        "source_case_count": len(rows),
        "decidable_source_case_count": decidable_case_count,
        "candidate_pair_count": candidate_pair_count,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "unknown_or_ambiguous_case_count": unknown_case_count,
        "excluded_unknown_pair_count": excluded_unknown_pair_count,
        "metrics": {
            "precision": {
                "value": _ratio(true_positive, precision_denominator),
                "numerator": true_positive,
                "denominator": precision_denominator,
            },
            "edge_recall": {
                "value": _ratio(true_positive, recall_denominator),
                "numerator": true_positive,
                "denominator": recall_denominator,
            },
            "edge_f1": {
                "value": _ratio(2 * true_positive, f1_denominator),
                "numerator": 2 * true_positive,
                "denominator": f1_denominator,
            },
        },
    }


def _audit_statistics(
    rows: Sequence[Mapping[str, Any]],
    *,
    bootstrap_iterations: int,
    seed_parts: Sequence[Any],
    frozen_bins: Mapping[str, Any],
) -> dict[str, Any]:
    edges = _edge_rows(rows)
    edge_stats = _edge_statistics(
        edges,
        parent_edges=edges,
        bootstrap_iterations=bootstrap_iterations,
        seed_parts=(*seed_parts, "edges"),
    )
    stages = sorted({str(edge["stage"]) for edge in edges})
    by_stage = {}
    for stage in stages:
        stage_edges = [edge for edge in edges if edge["stage"] == stage]
        stats = _edge_statistics(
            stage_edges,
            parent_edges=edges,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "stage", stage),
        )
        stats["stage_recall"] = {
            "value": None,
            "defined": False,
            "reason": (
                "No stage-eligible source-variable denominator exists; stages "
                "are assigned only after a match is accepted."
            ),
        }
        by_stage[stage] = stats

    score_boundaries = frozen_bins["score_boundaries"]
    gap_boundaries = frozen_bins["minimum_runner_up_gap_boundaries"]
    score_bins = sorted({_bin_label(edge.get("score"), score_boundaries) for edge in edges})
    gap_bins = sorted(
        {_bin_label(edge.get("minimum_runner_up_gap"), gap_boundaries) for edge in edges}
    )
    by_score = {
        label: _edge_statistics(
            [edge for edge in edges if _bin_label(edge.get("score"), score_boundaries) == label],
            parent_edges=edges,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "score-bin", label),
        )
        for label in score_bins
    }
    by_gap = {
        label: _edge_statistics(
            [
                edge
                for edge in edges
                if _bin_label(
                    edge.get("minimum_runner_up_gap"),
                    gap_boundaries,
                )
                == label
            ],
            parent_edges=edges,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "gap-bin", label),
        )
        for label in gap_bins
    }
    return {
        "source_relations": _source_statistics(
            rows,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "source"),
        ),
        "candidate_edge_confusion": _candidate_edge_confusion(rows),
        "accepted_edges": edge_stats,
        "by_matcher_stage": by_stage,
        "by_score_bin": by_score,
        "by_minimum_runner_up_gap_bin": by_gap,
    }


def _status_strata(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    cases = Counter(str(row.get("backend_status")) for row in rows)
    function_status: dict[tuple[str, str], str] = {}
    for row in rows:
        key = (str(row["audit_sample_id"]), str(row["backend_id"]))
        status = str(row.get("backend_status"))
        previous = function_status.setdefault(key, status)
        if previous != status:
            raise ValueError(f"backend status changes within relation group {key}")
    functions = Counter(function_status.values())
    return {
        "case_counts": dict(sorted(cases.items())),
        "source_function_backend_counts": dict(sorted(functions.items())),
    }


def _stratified_statistics(
    rows: Sequence[Mapping[str, Any]],
    *,
    bootstrap_iterations: int,
    seed_parts: Sequence[Any],
    frozen_bins: Mapping[str, Any],
) -> dict[str, Any]:
    matcher_rows = [row for row in rows if row.get("backend_status") == "ok"]
    return {
        "backend_status_strata": _status_strata(rows),
        "matcher_conditional_on_backend_ok": _audit_statistics(
            matcher_rows,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "matcher-ok"),
            frozen_bins=frozen_bins,
        ),
        "end_to_end_pipeline": _audit_statistics(
            rows,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=(*seed_parts, "end-to-end"),
            frozen_bins=frozen_bins,
        ),
    }


def make_audit_report(
    joined: Sequence[Mapping[str, Any]],
    *,
    manifest: Mapping[str, Any],
    bootstrap_iterations: int,
) -> dict[str, Any]:
    if bootstrap_iterations < 0:
        raise ValueError("bootstrap_iterations must be non-negative")
    frozen_bins = manifest["frozen_bins"]
    backends = sorted({str(row["backend_id"]) for row in joined})
    partitions = sorted(
        {
            str(row["partition"])
            for row in joined
            if isinstance(row.get("partition"), str) and row.get("partition")
        }
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "local-variable-semantic-audit-report",
        "package_manifest_payload_sha256": manifest["manifest_payload_sha256"],
        "bootstrap": {
            "cluster_unit": "source function (audit_sample_id)",
            "iterations": bootstrap_iterations,
            "seed_algorithm": "sha256 deterministic",
        },
        "frozen_bins": frozen_bins,
        "pipeline_coverage": manifest["coverage"],
        "summary": _stratified_statistics(
            joined,
            bootstrap_iterations=bootstrap_iterations,
            seed_parts=("all",),
            frozen_bins=frozen_bins,
        ),
        "by_backend": {
            backend: _stratified_statistics(
                [row for row in joined if row["backend_id"] == backend],
                bootstrap_iterations=bootstrap_iterations,
                seed_parts=("backend", backend),
                frozen_bins=frozen_bins,
            )
            for backend in backends
        },
        "by_partition": {
            partition: _stratified_statistics(
                [row for row in joined if row.get("partition") == partition],
                bootstrap_iterations=bootstrap_iterations,
                seed_parts=("partition", partition),
                frozen_bins=frozen_bins,
            )
            for partition in partitions
        },
        "by_backend_partition": {
            backend: {
                partition: _stratified_statistics(
                    [
                        row
                        for row in joined
                        if row["backend_id"] == backend and row.get("partition") == partition
                    ],
                    bootstrap_iterations=bootstrap_iterations,
                    seed_parts=("backend-partition", backend, partition),
                    frozen_bins=frozen_bins,
                )
                for partition in partitions
            }
            for backend in backends
        },
        "interpretation": {
            "valid_edge_precision": (
                "correct, split, merge, and many-to-many selected edges among "
                "decidable accepted edges"
            ),
            "strict_one_to_one_precision": (
                "only one-to-one correct accepted edges among decidable edges"
            ),
            "wrong_edge_error_bounds": (
                "lower treats oracle-unknown edges as valid; upper treats all "
                "oracle-unknown edges as wrong"
            ),
            "matcher_conditioning": (
                "matcher accuracy/recall excludes non-ok backend strata; end-to-end "
                "source-variable results retain missing/error cases with auditable "
                "source variables; source-error and zero-observable functions are "
                "coverage-only"
            ),
            "matcher_relation_recall": (
                "source-level any-neighbor hit rate: a mapped source variable counts "
                "when the matcher accepts any reviewer-selected decompiler neighbor; "
                "this is not complete oracle-edge or full-relation recall for splits"
            ),
            "matcher_oracle_edge_recall": (
                "accepted reviewer-selected semantic edges divided by all "
                "reviewer-selected semantic edges"
            ),
            "matcher_full_relation_recall": (
                "mapped source variables whose complete accepted-neighbor set exactly "
                "equals the reviewer-selected neighbor set"
            ),
            "candidate_edge_confusion": (
                "for each decidable source-variable case, every distinct "
                "reviewer-visible decompiler-variable alias is one evaluation edge; "
                "TP means matcher and reviewer selected it, FP matcher only, FN "
                "reviewer only, and TN neither. Oracle-unknown and ambiguous cases "
                "are excluded with their pair counts reported separately"
            ),
            "candidate_edge_accuracy": (
                "intentionally omitted because the many irrelevant true-negative "
                "pairs make accuracy and cross-backend TN comparisons misleading"
            ),
            "stage_recall": (
                "undefined because matcher stages have no pre-acceptance eligible "
                "source denominator"
            ),
        },
    }


def apply_reviewer_decisions(
    shard_path: Path,
    decisions_path: Path,
    output_path: Path,
    *,
    reviewer: str,
) -> dict[str, Any]:
    """Safely apply compact JSONL decisions to one public reviewer shard.

    This function has no package/checkpoint/private-join parameter and never
    reads private matcher data.
    """

    if not reviewer.strip():
        raise ValueError("reviewer must be nonempty")
    shard = _read_json(shard_path)
    _validate_reviewer_shard_schema(shard, f"reviewer shard {shard_path}")
    shard_id = shard.get("shard_id")
    if not isinstance(shard_id, str) or not shard_id:
        raise ValueError(f"{shard_path}: invalid shard_id")
    evidence_rows = shard.get("evidence")
    cases = shard.get("cases")
    if not isinstance(evidence_rows, list) or not isinstance(cases, list):
        raise ValueError(f"{shard_path}: public evidence/cases are missing")
    for evidence in evidence_rows:
        if not isinstance(evidence, dict):
            raise ValueError(f"{shard_path}: invalid public evidence")
        validate_public_evidence(evidence)
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(f"{shard_path}: invalid public case")
        validate_public_case(case)
        if case.get("shard_id") != shard_id:
            raise ValueError(f"{shard_path}: case belongs to another shard")
    immutable = _shard_public_payload(shard_id, evidence_rows, cases)
    immutable_hash = evidence_sha256(immutable)
    if immutable_hash != shard.get("public_payload_sha256"):
        raise ValueError(f"{shard_path}: public payload SHA-256 mismatch")

    decisions = read_jsonl(decisions_path)
    allowed_fields = {
        "schema_version",
        "case_id",
        "oracle_status",
        "selected_decompiled_audit_ids",
        "confidence",
        "rationale",
    }
    by_case: dict[str, dict[str, Any]] = {}
    for row_number, decision in enumerate(decisions, start=1):
        extra = set(decision) - allowed_fields
        if extra:
            raise ValueError(
                f"{decisions_path}:{row_number}: unsupported decision fields " f"{sorted(extra)}"
            )
        if decision.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"{decisions_path}:{row_number}: unsupported schema_version")
        case_id = decision.get("case_id")
        if not isinstance(case_id, str):
            raise ValueError(f"{decisions_path}:{row_number}: case_id is required")
        if case_id in by_case:
            raise ValueError(f"{decisions_path}:{row_number}: duplicate case_id {case_id}")
        by_case[case_id] = decision
    expected = {str(case["case_id"]) for case in cases}
    if set(by_case) != expected:
        raise ValueError(
            f"{decisions_path}: decision coverage mismatch; "
            f"missing={len(expected - set(by_case))} "
            f"extra={len(set(by_case) - expected)}"
        )
    completed: list[dict[str, Any]] = []
    for case in cases:
        template = _label_template(case)
        decision = by_case[str(case["case_id"])]
        completed.append(
            {
                **template,
                "oracle_status": decision.get("oracle_status"),
                "selected_decompiled_audit_ids": decision.get(
                    "selected_decompiled_audit_ids",
                    [],
                ),
                "confidence": decision.get("confidence"),
                "rationale": decision.get("rationale", ""),
                "reviewer": reviewer,
            }
        )
    validate_labels(
        completed,
        cases,
        evidence_rows,
        require_complete=True,
        expected_case_ids=expected,
        reviewer_assignment=reviewer,
    )
    result = {
        **immutable,
        "public_payload_sha256": immutable_hash,
        "reviewer_assignment": reviewer,
        "labels": completed,
    }
    write_json(output_path, result)
    return {
        "shard_id": shard_id,
        "case_count": len(completed),
        "reviewer_assignment": reviewer,
        "output_sha256": _file_sha256(output_path),
    }


def _validate_merge_provenance(
    package_dir: Path,
    manifest: Mapping[str, Any],
    labels_path: Path,
    provenance_path: Path | None,
) -> dict[str, Any]:
    path = provenance_path or package_dir / MERGE_PROVENANCE_FILENAME
    provenance = _read_json(path)
    _require_schema(provenance, MERGE_KIND, "label merge provenance")
    _require_exact_keys(
        provenance,
        {
            "schema_version",
            "kind",
            "package_manifest_payload_sha256",
            "complete",
            "case_count",
            "label_file",
            "label_file_sha256",
            "inputs",
            "merge_payload_sha256",
        },
        "label merge provenance",
    )
    payload = dict(provenance)
    claimed = payload.pop("merge_payload_sha256", None)
    if not isinstance(claimed, str) or evidence_sha256(payload) != claimed:
        raise ValueError("label merge provenance SHA-256 mismatch")
    if provenance.get("package_manifest_payload_sha256") != manifest.get("manifest_payload_sha256"):
        raise ValueError("label merge provenance names a different package")
    if provenance.get("complete") is not True:
        raise ValueError("label merge provenance is not a complete merge")
    if provenance.get("label_file_sha256") != _file_sha256(labels_path):
        raise ValueError("label merge provenance/label file digest mismatch")
    if provenance.get("case_count") != manifest.get("case_count"):
        raise ValueError("label merge provenance case count mismatch")
    inputs = provenance.get("inputs")
    if not isinstance(inputs, list):
        raise ValueError("label merge provenance has no reviewer inputs")
    if any(not isinstance(entry, dict) for entry in inputs):
        raise ValueError("label merge provenance has an invalid reviewer input")
    for index, entry in enumerate(inputs):
        _require_exact_keys(
            entry,
            {
                "shard_id",
                "reviewer_assignment",
                "input_file_sha256",
                "public_payload_sha256",
                "case_count",
            },
            f"label merge provenance input {index}",
        )
    shard_ids = [entry.get("shard_id") for entry in inputs]
    if len(shard_ids) != len(set(shard_ids)):
        raise ValueError("label merge provenance contains duplicate shards")
    shard_manifest = _read_json(package_dir / SHARD_DIRNAME / SHARD_MANIFEST_FILENAME)
    expected_shards = {str(entry["shard_id"]) for entry in shard_manifest.get("shards", [])}
    if set(shard_ids) != expected_shards:
        raise ValueError("label merge provenance shard coverage is incomplete")
    if sum(int(entry.get("case_count", -1)) for entry in inputs) != manifest.get("case_count"):
        raise ValueError("label merge provenance input case counts are inconsistent")
    assignment_by_shard: dict[str, str] = {}
    for entry in inputs:
        assignment = entry.get("reviewer_assignment")
        input_digest = entry.get("input_file_sha256")
        if (
            not isinstance(assignment, str)
            or not assignment.strip()
            or not isinstance(input_digest, str)
        ):
            raise ValueError("label merge provenance reviewer input is incomplete")
        assignment_by_shard[str(entry["shard_id"])] = assignment
    label_assignments: dict[str, set[str]] = defaultdict(set)
    for label in read_jsonl(labels_path):
        label_assignments[str(label.get("shard_id"))].add(str(label.get("reviewer")))
    if set(label_assignments) != expected_shards or any(
        reviewers != {assignment_by_shard[shard_id]}
        for shard_id, reviewers in label_assignments.items()
    ):
        raise ValueError("label reviewers do not match merge shard assignments")
    return provenance


def join_audit_package(
    package_dir: Path,
    *,
    labels_path: Path | None = None,
    merge_provenance_path: Path | None = None,
    bootstrap_iterations: int = 2000,
    allow_incomplete: bool = False,
) -> dict[str, Any]:
    """Validate, privately join, and report a completed semantic audit."""

    actual_labels = labels_path or package_dir / LABEL_FILENAME
    manifest, evidence_rows, cases, private_rows, labels = _load_package(
        package_dir,
        actual_labels,
        require_complete=not allow_incomplete,
    )
    if not allow_incomplete:
        _validate_merge_provenance(
            package_dir,
            manifest,
            actual_labels,
            merge_provenance_path,
        )
    joined = join_audit_rows(
        evidence_rows,
        cases,
        private_rows,
        labels,
    )
    report = make_audit_report(
        joined,
        manifest=manifest,
        bootstrap_iterations=bootstrap_iterations,
    )
    write_jsonl(package_dir / JOINED_FILENAME, joined, private=True)
    write_json(package_dir / REPORT_FILENAME, report)
    return report
