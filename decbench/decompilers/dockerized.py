"""Container-backed and external-tool decompiler plugins.

This module hosts decompilers that decbench does **not** drive through declib,
because they ship as standalone CLIs rather than Python libraries:

- **Reko** (``reko``) — .NET decompiler, run inside a Docker image.
- **RetDec** (``retdec``) — LLVM-based decompiler, run inside a Docker image.
- **r2dec** (``r2dec``) — radare2's r2dec decompiler. Discovers functions from
  radare2's OWN analysis (``aaa`` + ``aflj``, so it works on fully STRIPPED
  ELF/PE and ARM firmware), normalizes addresses to ELF-file space, and
  decompiles each function with the r2dec ``pdd`` command — falling back to the
  built-in ``pdc`` pseudo-decompiler when the r2dec plugin is absent. It picks,
  in order, native-with-plugin > the ``decbench/r2dec`` Docker image (real
  r2dec built from source; the host's packaged r2 usually lacks the dev headers
  to build the plugin natively) > native ``pdc``. A version-configured image is
  an explicit pin and takes precedence over every native path. Unlike the whole-program
  RetDec/Reko path, r2dec does NOT go through the ELF symbol table or
  ``split_c_functions`` — its discovery and per-function decompile are
  symbol-free and address-keyed, matching how the benchmark driver hands it a
  stripped binary + a set of DWARF ``low_pc`` addresses.

Common design (:class:`DockerizedDecompiler`):
    The container is run with the target binary bind-mounted **read-only**; the
    decompiler emits whole-program C, which we then split into per-function
    snippets. Function *names and addresses* come from the binary's ELF symbol
    table (via pyelftools), so addresses live in **ELF file space** and line up
    with DWARF and the rest of decbench — the same convention declib_dec uses.

    These tools do not expose provenance uniformly. RetDec supplies native line
    and variable evidence from annotated JSON and DSM output. Reko's image emits
    a sidecar that carries exact final-identifier identity through its lower IR
    and structured AST, yielding native variable access addresses without a line
    map. r2dec attaches ``pddj`` line offsets plus ``afv*`` variable metadata and
    access addresses when available. Older images retain the text-only fallback,
    and the metrics degrade gracefully to syntax and usage evidence when optional
    provenance is absent.

Images are **not** auto-built. ``is_available()`` only reports whether the image
already exists locally; build it explicitly with ``decbench decompiler-build
<name>`` (which builds the image resolved for that decompiler spec).
"""

from __future__ import annotations

import contextlib
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common as raw_common
from decbench.decompilers.registry import register_decompiler
from decbench.decompilers.spec import version_settings
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
    VariableOccurrencePolicy,
    with_variable_occurrence_policy,
)
from decbench.utils import binfmt
from decbench.utils.docker_task import docker_task_label_args

_l = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_DIR = _REPO_ROOT / "docker"
_RETDEC_KEEP_SIDECARS_ENV = "DECBENCH_RETDEC_KEEP_SIDECARS"
_RETDEC_SIDECAR_NAMES = ("out.json", "out.dsm")
_RETDEC_SIDECAR_SCHEMA = "decbench-retdec-raw-sidecars-v1"


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _open_retdec_regular_file(path: Path) -> BinaryIO:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"RetDec raw artifact is unavailable: {path}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError(f"RetDec raw artifact is not a single-link regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"RetDec raw artifact could not be opened safely: {path}") from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"RetDec raw artifact changed while opening: {path}")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _retdec_regular_sha256(path: Path) -> str:
    with _open_retdec_regular_file(path) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _read_retdec_regular_text(path: Path) -> str:
    with _open_retdec_regular_file(path) as stream:
        return stream.read().decode(errors="replace")


def _retdec_sidecar_destination(
    binary_path: Path,
    output_dir: Path,
) -> tuple[Path, str]:
    binary_digest = _file_sha256(binary_path)
    name_digest = hashlib.sha256(binary_path.name.encode()).hexdigest()
    return output_dir / "retdec-sidecars" / binary_digest / name_digest, binary_digest


def _retdec_sidecars_match(destination: Path, digests: dict[str, str]) -> bool:
    try:
        if destination.is_symlink() or not destination.is_dir():
            return False
        files = list(destination.iterdir())
        return {path.name for path in files} == set(_RETDEC_SIDECAR_NAMES) and all(
            not path.is_symlink()
            and path.is_file()
            and path.stat().st_nlink == 1
            and _retdec_regular_sha256(path) == digests[path.name]
            for path in files
        )
    except (OSError, RuntimeError):
        return False


def _require_retdec_artifact_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"RetDec raw sidecar directory is a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"RetDec raw sidecar path is not a regular directory: {path}")


def _quarantine_retdec_artifacts(
    paths: list[Path],
    output_dir: Path,
    binary_digest: str,
    name_digest: str,
) -> list[Path]:
    quarantine_root = output_dir / "retdec-sidecars-quarantine"
    _require_retdec_artifact_directory(quarantine_root)
    binary_root = quarantine_root / binary_digest
    _require_retdec_artifact_directory(binary_root)
    quarantine = binary_root / name_digest
    _require_retdec_artifact_directory(quarantine)
    destinations = [quarantine / path.name for path in paths]
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise RuntimeError("RetDec raw sidecar quarantine destination already exists")
    for source, destination in zip(paths, destinations, strict=True):
        source.rename(destination)
    return destinations


def _persist_retdec_sidecars(
    binary_path: Path,
    work_dir: Path,
    output_dir: Path,
) -> dict[str, object]:
    sources = {name: work_dir / name for name in _RETDEC_SIDECAR_NAMES}
    missing = [
        name for name, path in sources.items() if not path.exists() and not path.is_symlink()
    ]
    if missing:
        raise RuntimeError(f"RetDec raw sidecar retention requires {', '.join(missing)}")

    destination, binary_digest = _retdec_sidecar_destination(binary_path, output_dir)
    digests = {name: _retdec_regular_sha256(path) for name, path in sources.items()}
    _require_retdec_artifact_directory(output_dir)
    sidecar_root = output_dir / "retdec-sidecars"
    _require_retdec_artifact_directory(sidecar_root)
    _require_retdec_artifact_directory(destination.parent)
    staging_prefix = f".{destination.name}."
    orphans = sorted(
        (path for path in destination.parent.iterdir() if path.name.startswith(staging_prefix)),
        key=lambda path: path.name,
    )
    if orphans:
        if (
            len(orphans) == 1
            and not destination.exists()
            and not destination.is_symlink()
            and _retdec_sidecars_match(orphans[0], digests)
        ):
            orphans[0].rename(destination)
        else:
            quarantined = _quarantine_retdec_artifacts(
                orphans,
                output_dir,
                binary_digest,
                destination.name,
            )
            names = ", ".join(str(path.relative_to(output_dir)) for path in quarantined)
            raise RuntimeError(f"RetDec orphan raw sidecar staging quarantined: {names}")

    if destination.exists() or destination.is_symlink():
        if not _retdec_sidecars_match(destination, digests):
            raise RuntimeError(f"RetDec raw sidecar destination conflicts: {destination}")
    else:
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
        try:
            for name, source in sources.items():
                target = staging / name
                with (
                    _open_retdec_regular_file(source) as source_stream,
                    target.open("xb") as target_stream,
                ):
                    shutil.copyfileobj(source_stream, target_stream)
                    target_stream.flush()
                    os.fsync(target_stream.fileno())
            try:
                staging.rename(destination)
            except OSError:
                if not destination.exists() or not _retdec_sidecars_match(destination, digests):
                    raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    if not _retdec_sidecars_match(destination, digests):
        quarantined = _quarantine_retdec_artifacts(
            [destination],
            output_dir,
            binary_digest,
            destination.name,
        )
        raise RuntimeError(
            "RetDec raw sidecar post-publication verification failed; quarantined: "
            f"{quarantined[0].relative_to(output_dir)}"
        )

    return {
        "schema": _RETDEC_SIDECAR_SCHEMA,
        "path": str(destination.relative_to(output_dir)),
        "binary_sha256": binary_digest,
        "out_json_sha256": digests["out.json"],
        "out_dsm_sha256": digests["out.dsm"],
    }


def _docker_image_version(image: str) -> str | None:
    """Return the tag or digest identifying an OCI image reference."""
    image = image.strip()
    if not image:
        return None
    if "@" in image:
        digest = image.rsplit("@", 1)[1]
        return digest or None
    final_component = image.rsplit("/", 1)[-1]
    if ":" in final_component:
        tag = final_component.rsplit(":", 1)[1]
        return tag or "latest"
    return "latest"


def elf_function_symbols(binary_path: Path) -> list[tuple[str, int]]:
    """Enumerate ``(name, address)`` for benchmarkable functions via ELF symbols.

    Addresses are in **ELF file space** (``st_value``), which matches DWARF and
    the declib-backed decompilers. CRT/compiler helpers, import thunks, and
    anything outside file-backed executable sections are filtered out. Returned
    sorted by address.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except Exception as e:  # noqa: BLE001
        _l.debug("pyelftools unavailable: %s", e)
        return []

    code_ranges = raw_common.executable_code_ranges(binary_path)
    out: dict[str, int] = {}
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    addr = int(sym["st_value"])
                    name = sym.name or ""
                    if not addr or not name:
                        continue
                    if raw_common.should_skip_function(name, addr, code_ranges):
                        continue
                    out.setdefault(name, addr)
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to enumerate symbols for %s: %s", binary_path, e)
        return []

    return sorted(out.items(), key=lambda kv: kv[1])


_FUNC_DEF_RE = re.compile(
    r"^[A-Za-z_][\w\s\*\(\),:<>\[\]&]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)" r"(?:\s*\{|\s*$)",
    re.MULTILINE,
)


def split_c_functions(combined_c: str) -> dict[str, str]:
    """Best-effort split of whole-program C into ``{function_name: snippet}``.

    Walks the source tracking brace depth. When a ``name(...)`` definition is
    seen at depth 0, with its opening brace on that line or a following line,
    everything up to the matching closing brace is captured for that name. Only
    top-level definitions are recorded (nested braces are balanced). This is
    heuristic — decompiler output is messy — and any function we cannot isolate
    simply won't get an individual snippet (callers fall back to other names or
    the combined source).
    """
    results: dict[str, str] = {}
    lines = combined_c.splitlines(keepends=True)
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _FUNC_DEF_RE.match(line)
        if m is None:
            i += 1
            continue
        name = m.group(1)
        depth = 0
        opened = False
        chunk: list[str] = []
        j = i
        while j < n:
            cur = lines[j]
            chunk.append(cur)
            stripped = _strip_c_literals(cur)
            depth += stripped.count("{")
            depth -= stripped.count("}")
            if "{" in stripped:
                opened = True
            if opened and depth <= 0:
                break
            j += 1
        snippet = "".join(chunk).rstrip() + "\n"
        results.setdefault(name, snippet)
        i = j + 1
    return results


def _strip_c_literals(line: str) -> str:
    """Remove the contents of string/char literals and line comments.

    Crude but good enough to stop ``"}"`` inside a string from unbalancing the
    brace counter. Not a real lexer.
    """
    line = re.sub(r"//.*", "", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


@dataclass(frozen=True)
class _RetDecToken:
    start: int
    end: int
    kind: str
    value: str
    occurrence_address: int | None


@dataclass(frozen=True)
class _RetDecFunction:
    name: str
    address: int | None
    code: str
    line_mappings: tuple[LineMapping, ...]
    variable_lines: dict[str, tuple[int, ...]]
    variable_addresses: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class _RetDecAnnotatedSource:
    text: str
    functions: dict[str, _RetDecFunction]


@dataclass(frozen=True)
class _RetDecAddressPolicy:
    thumb_entries: frozenset[int] = frozenset()

    def key(self, address: int) -> int:
        canonical = address & ~1
        return canonical if canonical in self.thumb_entries else address


@dataclass(frozen=True)
class _RetDecBindingIndex:
    by_name: dict[str, _RetDecFunction]
    by_address: dict[int, _RetDecFunction]
    blocked_names: frozenset[str]
    blocked_addresses: frozenset[int]
    address_policy: _RetDecAddressPolicy


_RETDEC_VARIABLE_KINDS = frozenset({"i_arg", "i_lvar", "i_var"})
_RETDEC_ORIGIN_IDENTIFIER_KINDS = _RETDEC_VARIABLE_KINDS | {"i_gvar"}
_RETDEC_SYNTHETIC_FUNCTION_RE = re.compile(r"function_([0-9a-fA-F]+)\Z")


def _retdec_address(value: object, image_base: int) -> int | None:
    if value in (None, ""):
        return None
    try:
        address = int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid RetDec address: {value!r}") from exc
    if address < 0:
        raise ValueError(f"invalid RetDec address: {value!r}")
    return address + image_base if image_base and address < image_base else address


def _matching_c_brace(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _c_function_spans(combined_c: str) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    prior_end = 0
    for match in _FUNC_DEF_RE.finditer(combined_c):
        if match.start() < prior_end:
            continue
        name = match.group(1)
        if name in _C_KEYWORDS:
            continue
        opening = combined_c.rfind("{", match.start(), match.end())
        if opening < 0:
            continue
        closing = _matching_c_brace(combined_c, opening)
        if closing is None:
            continue
        newline = combined_c.find("\n", closing + 1)
        end = len(combined_c) if newline < 0 else newline + 1
        spans.append((name, match.start(), end))
        prior_end = end
    return spans


def _retdec_dsm_evidence(
    dsm: str,
    image_base: int,
) -> tuple[frozenset[int], tuple[tuple[int, int], ...]]:
    instruction_re = re.compile(r"^0x([0-9a-fA-F]+):.*\t", re.MULTILINE)
    range_re = re.compile(
        r"^; function: .*? at (0x[0-9a-fA-F]+) -- (0x[0-9a-fA-F]+)\s*$",
        re.MULTILINE,
    )
    instructions = frozenset(
        address
        for match in instruction_re.finditer(dsm)
        if (address := _retdec_address(f"0x{match.group(1)}", image_base)) is not None
    )
    ranges: list[tuple[int, int]] = []
    for match in range_re.finditer(dsm):
        start = _retdec_address(match.group(1), image_base)
        end = _retdec_address(match.group(2), image_base)
        if start is not None and end is not None and start < end:
            ranges.append((start, end))
    return instructions, tuple(sorted(set(ranges)))


def _retdec_function_range(
    address: int | None,
    ranges: tuple[tuple[int, int], ...] | None,
) -> tuple[int, int] | None:
    if address is None or ranges is None:
        return None
    exact = next((item for item in ranges if item[0] == address), None)
    if exact is not None:
        return exact
    return next((item for item in ranges if item[0] <= address < item[1]), None)


def _retdec_accepts_address(
    address: int | None,
    valid_instruction_addresses: frozenset[int] | None,
    function_range: tuple[int, int] | None,
    require_function_range: bool,
) -> bool:
    if address is None:
        return False
    if valid_instruction_addresses is not None and address not in valid_instruction_addresses:
        return False
    if require_function_range:
        return function_range is not None and function_range[0] <= address < function_range[1]
    return True


def _retdec_synthetic_address(name: str, image_base: int) -> int | None:
    match = _RETDEC_SYNTHETIC_FUNCTION_RE.fullmatch(name)
    if match is None:
        return None
    return _retdec_address(f"0x{match.group(1)}", image_base)


def _retdec_synthetic_entry(
    name: str,
    image_base: int,
    valid_instruction_addresses: frozenset[int] | None,
    function_range_start_counts: Counter[int] | None,
    name_count: int,
    address_count: int,
) -> int | None:
    address = _retdec_synthetic_address(name, image_base)
    if address is None or name_count != 1 or address_count != 1:
        return None
    return (
        address
        if _retdec_has_exact_dsm_entry(
            address,
            valid_instruction_addresses,
            function_range_start_counts,
        )
        else None
    )


def _retdec_has_exact_dsm_entry(
    address: int,
    valid_instruction_addresses: frozenset[int] | None,
    function_range_start_counts: Counter[int] | None,
) -> bool:
    return (
        valid_instruction_addresses is not None
        and address in valid_instruction_addresses
        and function_range_start_counts is not None
        and function_range_start_counts[address] == 1
    )


def _retdec_address_policy(
    binary_path: Path,
    annotated: _RetDecAnnotatedSource | None,
    base_bindings: dict[str, int],
    target_addresses: set[int],
) -> _RetDecAddressPolicy:
    info = binfmt.detect(binary_path)
    if info is None or info.arch != "arm":
        return _RetDecAddressPolicy()

    addresses = set(base_bindings.values()) | target_addresses
    if annotated is not None:
        addresses.update(
            function.address
            for function in annotated.functions.values()
            if function.address is not None
        )
    mclass = info.fmt == "elf" and binfmt.elf_is_arm_mclass(binary_path)
    return _RetDecAddressPolicy(
        frozenset(address & ~1 for address in addresses if mclass or address & 1)
    )


def _retdec_binding_index(
    annotated: _RetDecAnnotatedSource,
    base_bindings: dict[str, int],
    address_policy: _RetDecAddressPolicy,
) -> _RetDecBindingIndex:
    address_groups: dict[int, list[_RetDecFunction]] = defaultdict(list)
    blocked_names: set[str] = set()
    blocked_addresses: set[int] = set()
    for key, function in annotated.functions.items():
        if key != function.name:
            blocked_names.update((key, function.name))
        if function.address is None:
            if _retdec_synthetic_address(function.name, 0) is not None:
                blocked_names.add(function.name)
            continue
        address_groups[address_policy.key(function.address)].append(function)

    for address, functions in address_groups.items():
        if len(functions) != 1:
            blocked_addresses.add(address)
            blocked_names.update(function.name for function in functions)

    for address, functions in address_groups.items():
        if len(functions) != 1:
            continue
        function = functions[0]
        bound_address = base_bindings.get(function.name)
        if bound_address is not None and address_policy.key(bound_address) != address:
            blocked_names.add(function.name)
            blocked_addresses.update((address, address_policy.key(bound_address)))

    for address in blocked_addresses:
        blocked_names.update(function.name for function in address_groups.get(address, ()))

    by_name: dict[str, _RetDecFunction] = {}
    by_address: dict[int, _RetDecFunction] = {}
    for address, functions in address_groups.items():
        if address in blocked_addresses or len(functions) != 1:
            continue
        function = functions[0]
        if function.name in blocked_names:
            continue
        by_name[function.name] = function
        by_address[address] = function
    return _RetDecBindingIndex(
        by_name=by_name,
        by_address=by_address,
        blocked_names=frozenset(blocked_names),
        blocked_addresses=frozenset(blocked_addresses),
        address_policy=address_policy,
    )


def _retdec_merge_bindings(
    base_bindings: dict[str, int],
    index: _RetDecBindingIndex,
) -> dict[str, int]:
    annotated_addresses = frozenset(index.by_address)
    merged = {
        name: address
        for name, address in base_bindings.items()
        if name not in index.blocked_names
        and index.address_policy.key(address) not in index.blocked_addresses
        and index.address_policy.key(address) not in annotated_addresses
    }
    for function in index.by_address.values():
        if function.address is not None:
            merged[function.name] = function.address
    return merged


def _parse_retdec_json(
    raw_json: str,
    *,
    image_base: int = 0,
    valid_instruction_addresses: frozenset[int] | None = None,
    function_ranges: tuple[tuple[int, int], ...] | None = None,
) -> _RetDecAnnotatedSource:
    payload = json.loads(raw_json)
    if not isinstance(payload, dict) or not isinstance(payload.get("tokens"), list):
        raise ValueError("RetDec JSON output has no token stream")
    if payload.get("language") not in (None, "C"):
        raise ValueError(f"unsupported RetDec output language: {payload.get('language')!r}")

    current_address: int | None = None
    previous_address: int | None = None
    address_changed = False
    parts: list[str] = []
    tokens: list[_RetDecToken] = []
    position = 0
    raw_tokens = payload["tokens"]
    for index, item in enumerate(raw_tokens):
        if not isinstance(item, dict):
            raise ValueError("RetDec token is not an object")
        if "addr" in item:
            previous_address = current_address
            current_address = _retdec_address(item["addr"], image_base)
            address_changed = True
        has_kind = "kind" in item
        has_value = "val" in item
        if not has_kind and not has_value:
            continue
        if not has_kind or not has_value:
            raise ValueError("RetDec token kind/value must appear together")
        kind = item["kind"]
        value = item["val"]
        if not isinstance(kind, str) or not isinstance(value, str):
            raise ValueError("RetDec token kind/value must be strings")
        occurrence_address = current_address
        # Defined Variable tokens temporarily carry their LLVM origin address;
        # an immediate restoration confirms the enclosing statement address.
        if address_changed and kind in _RETDEC_ORIGIN_IDENTIFIER_KINDS:
            next_item = raw_tokens[index + 1] if index + 1 < len(raw_tokens) else None
            if isinstance(next_item, dict) and "addr" in next_item:
                restored_address = _retdec_address(next_item["addr"], image_base)
                if restored_address == previous_address:
                    occurrence_address = previous_address
        end = position + len(value)
        tokens.append(_RetDecToken(position, end, kind, value, occurrence_address))
        parts.append(value)
        position = end
        previous_address = None
        address_changed = False

    text = "".join(parts)
    spans = _c_function_spans(text)
    span_name_counts = Counter(name for name, _start, _end in spans)
    synthetic_addresses = [
        address
        for name, _start, _end in spans
        if (address := _retdec_synthetic_address(name, image_base)) is not None
    ]
    synthetic_address_counts = Counter(synthetic_addresses)
    function_range_start_counts = (
        Counter(start for start, _end in function_ranges) if function_ranges is not None else None
    )
    functions: dict[str, _RetDecFunction] = {}
    for name, start, end in spans:
        code = text[start:end]
        opening = code.find("{")
        header_end = end if opening < 0 else start + opening
        function_tokens = [token for token in tokens if start <= token.start < end]
        token_entries = {
            token.occurrence_address
            for token in function_tokens
            if token.start < header_end
            and token.kind == "i_fnc"
            and token.value == name
            and token.occurrence_address is not None
        }
        synthetic_address = _retdec_synthetic_address(name, image_base)
        synthetic_entry = False
        fallback_entry = _retdec_synthetic_entry(
            name,
            image_base,
            valid_instruction_addresses,
            function_range_start_counts,
            span_name_counts[name],
            synthetic_address_counts[synthetic_address] if synthetic_address is not None else 0,
        )
        synthetic_conflict = synthetic_address is not None and (
            span_name_counts[name] != 1 or synthetic_address_counts[synthetic_address] != 1
        )
        if synthetic_conflict:
            entry = None
        elif len(token_entries) == 1:
            entry = next(iter(token_entries))
            if synthetic_address is not None and entry != synthetic_address:
                if _retdec_has_exact_dsm_entry(
                    entry,
                    valid_instruction_addresses,
                    function_range_start_counts,
                ):
                    entry = None
                else:
                    entry = fallback_entry
                    synthetic_entry = entry is not None
        elif token_entries:
            entry = None
        else:
            entry = fallback_entry
            synthetic_entry = entry is not None
        function_range = _retdec_function_range(entry, function_ranges)

        starts = raw_common.line_starts(code)
        line_addresses: dict[int, set[int]] = defaultdict(set)
        if synthetic_entry and entry is not None:
            line_addresses[1].add(entry)
        variable_lines: dict[str, set[int]] = defaultdict(set)
        variable_addresses: dict[str, set[int]] = defaultdict(set)
        for token in function_tokens:
            if not token.value:
                continue
            line = raw_common.pos_to_line(token.start - start, starts)
            accepted = not (synthetic_entry and line == 1) and (
                _retdec_accepts_address(
                    token.occurrence_address,
                    valid_instruction_addresses,
                    function_range,
                    function_ranges is not None,
                )
            )
            if accepted and token.occurrence_address is not None:
                line_addresses[line].add(int(token.occurrence_address))
            if token.kind not in _RETDEC_VARIABLE_KINDS or not token.value:
                continue
            variable_lines[token.value].add(line)
            if accepted and token.occurrence_address is not None:
                variable_addresses[token.value].add(int(token.occurrence_address))

        functions.setdefault(
            name,
            _RetDecFunction(
                name=name,
                address=entry,
                code=code,
                line_mappings=tuple(raw_common.merge_line_addresses(line_addresses)),
                variable_lines={
                    variable: tuple(sorted(lines))
                    for variable, lines in sorted(variable_lines.items())
                },
                variable_addresses={
                    variable: tuple(sorted(addresses))
                    for variable, addresses in sorted(variable_addresses.items())
                },
            ),
        )
    return _RetDecAnnotatedSource(text=text, functions=functions)


def _retdec_variables(function: _RetDecFunction) -> list[VariableInfo]:
    try:
        from decbench.metrics.type_match import parse_c_variables
        from decbench.metrics.variable_features import analyze_c_function

        variables = list(parse_c_variables(function.code, function.name))
        analysis = analyze_c_function(
            function.code,
            function.name,
            (variable.name for variable in variables),
        )
    except Exception:  # noqa: BLE001
        return []

    counts = Counter(variable.name for variable in variables if variable.name)
    ambiguous = set(analysis.ambiguous_names)
    ambiguous.update(name for name, count in counts.items() if count != 1)
    enriched: list[VariableInfo] = []
    for variable in variables:
        if not variable.name or variable.name in ambiguous:
            enriched.append(variable)
            continue
        lines = list(function.variable_lines.get(variable.name, ()))
        addresses = list(function.variable_addresses.get(variable.name, ()))
        enriched.append(
            variable.model_copy(
                update={
                    "line_numbers": lines,
                    "addresses": addresses,
                }
            )
        )
    return enriched


class DockerizedDecompiler(Decompiler):
    """Base for decompilers run inside a Docker container.

    Subclasses set :attr:`image` (tag), :attr:`dockerfile` (file under
    ``docker/``), and implement :meth:`_container_decompile`, which runs the
    container against a mounted binary and returns whole-program C, optionally
    with native provenance.
    """

    name = "dockerized"
    display_name = "Dockerized Decompiler"

    image: str = ""
    dockerfile: str = ""
    container_timeout: float = 1800.0

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._version_image_configured = False
        if config is not None and config.binary_timeout_seconds:
            self.container_timeout = float(config.binary_timeout_seconds)

    def _configure_requested_version(self) -> None:
        settings = version_settings(self.name, self.requested_version)
        if "image" not in settings:
            return
        image = settings["image"]
        if not isinstance(image, str) or not image.strip():
            raise ValueError(f"invalid image for {self.id}: {image!r}")
        self.image = image.strip()
        self._version_image_configured = True

    @staticmethod
    def _docker_bin() -> str | None:
        return shutil.which("docker")

    @classmethod
    def _image_present(cls, image: str) -> bool:
        docker = shutil.which("docker")
        if not docker or not image:
            return False
        try:
            proc = subprocess.run(
                [docker, "image", "inspect", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            return proc.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        """True iff the docker binary is present AND the image exists locally.

        Never builds the image (that would be a surprising, multi-minute side
        effect). Use ``decbench decompiler-build <name>`` to build it first.
        """
        return self._image_present(self.image)

    @classmethod
    def build_image(
        cls,
        no_cache: bool = False,
        *,
        image: str | None = None,
    ) -> int:
        """Build this backend's Docker image. Returns the ``docker build`` rc.

        Equivalent to ``docker build -f docker/<dockerfile> -t <image> docker/``
        (the ``docker/`` directory is the build context, so images can COPY the
        helper scripts living there). ``image`` overrides the class default
        without mutating it.
        """
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        target_image = cls.image if image is None else image
        if not isinstance(target_image, str) or not target_image.strip() or not cls.dockerfile:
            raise RuntimeError(f"{cls.__name__} has no image/dockerfile configured")
        target_image = target_image.strip()

        dockerfile_path = _DOCKER_DIR / cls.dockerfile
        if not dockerfile_path.is_file():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

        cmd = [
            docker,
            "build",
            "-f",
            str(dockerfile_path),
            "-t",
            target_image,
        ]
        if no_cache:
            cmd.append("--no-cache")
        cmd.append(str(_DOCKER_DIR))
        _l.info("Building %s: %s", target_image, " ".join(cmd))
        proc = subprocess.run(cmd)
        return proc.returncode

    def build_configured_image(self, no_cache: bool = False) -> int:
        """Build the image realized for this registry-created instance."""
        return type(self).build_image(no_cache=no_cache, image=self.image)

    def get_version(self) -> str | None:
        return _docker_image_version(self.image)

    def _container_decompile(
        self,
        binary_path: Path,
        work_dir: Path,
    ) -> str | _RetDecAnnotatedSource:
        """Run the container and return whole-program C, optionally annotated.

        ``work_dir`` is a host temp dir bind-mounted into the container so the
        tool can write outputs there. Subclasses implement the tool-specific
        ``docker run`` invocation. Must raise on hard failure.
        """
        raise NotImplementedError

    def _persist_raw_artifacts(
        self,
        binary_path: Path,
        work_dir: Path,
        output_dir: Path | None,
    ) -> dict[str, object]:
        return {}

    def _run_docker(
        self,
        args: list[str],
        binary_path: Path,
        work_dir: Path,
        timeout: float | None = None,
        readonly_mounts: list[tuple[Path, str]] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``docker run`` with the binary mounted read-only at ``/in/<name>``
        and ``work_dir`` mounted read-write at ``/work``.

        ``args`` are appended after the image name (the container command). Use
        the placeholders ``/in/<binary_name>`` and ``/work`` in ``args``.
        ``readonly_mounts`` binds host files into exact container paths before
        the image name.
        """
        docker = self._docker_bin()
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        cmd = [
            docker,
            "run",
            "--rm",
            *docker_task_label_args(),
            "-v",
            f"{binary_path.resolve()}:/in/{binary_path.name}:ro",
            "-v",
            f"{work_dir.resolve()}:/work",
        ]
        for host_path, container_path in readonly_mounts or []:
            resolved = host_path.resolve()
            if not resolved.is_file():
                raise FileNotFoundError(f"Docker bind source not found: {resolved}")
            cmd.extend(["-v", f"{resolved}:{container_path}:ro"])
        cmd.extend([self.image, *args])
        _l.debug("docker run: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or self.container_timeout,
        )

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary inside the container and split into functions.

        Args:
            functions: optional ``(name, address)`` allowlist (addresses in ELF
                space). When None, all ELF-symbol functions are considered.
            function_names: optional ELF-file-space address filter, with legacy
                string-name support.
            output_dir / progress_path: parity with the declib path; outputs are
                written to ``output_dir`` if given. ``progress_path`` is accepted
                for driver compatibility (whole-program tools run atomically, so
                there is no per-function checkpoint to write).
        """
        if not self.is_available():
            raise RuntimeError(
                f"Decompiler '{self.id}' is not available "
                f"(image '{self.image}' missing — run `decbench decompiler-build "
                f"{self.id}`)"
            )

        start = time.time()
        timed_out = False
        combined_c: str | _RetDecAnnotatedSource = ""
        error: str | None = None
        artifact_metadata: dict[str, object] = {}

        with tempfile.TemporaryDirectory(prefix=f"decbench_{self.name}_") as td:
            work_dir = Path(td)
            try:
                produced = self._container_decompile(binary_path, work_dir)
            except subprocess.TimeoutExpired as e:
                timed_out = True
                error = f"timeout after {self.container_timeout}s"
                _l.warning("%s timed out on %s: %s", self.name, binary_path, e)
            except Exception as e:  # noqa: BLE001
                error = str(e)
                _l.error("%s failed on %s: %s", self.name, binary_path, e)
            else:
                combined_c = produced
            try:
                artifact_metadata = self._persist_raw_artifacts(
                    binary_path,
                    work_dir,
                    output_dir,
                )
            except Exception as e:  # noqa: BLE001
                combined_c = ""
                retention_error = f"raw artifact retention failed: {e}"
                error = f"{error}; {retention_error}" if error else retention_error
                _l.error("%s failed on %s: %s", self.name, binary_path, retention_error)

        result = self._build_result(
            binary_path=binary_path,
            combined_c=combined_c,
            functions=functions,
            function_names=function_names,
            elapsed=time.time() - start,
            timed_out=timed_out,
            error=error,
            output_dir=output_dir,
        )
        if artifact_metadata:
            result.decompiler.extra = {
                **(result.decompiler.extra or {}),
                "raw_sidecars": artifact_metadata,
            }

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            with contextlib.suppress(Exception):
                result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    def _build_result(
        self,
        binary_path: Path,
        combined_c: str | _RetDecAnnotatedSource,
        functions: list[tuple[str, int]] | None,
        function_names: set[int] | set[str] | None,
        elapsed: float,
        timed_out: bool,
        error: str | None,
        output_dir: Path | None,
    ) -> DecompilationResult:
        """Assemble a :class:`DecompilationResult` from whole-program C."""
        if isinstance(combined_c, _RetDecAnnotatedSource):
            annotated: _RetDecAnnotatedSource | None = combined_c
            source_text = combined_c.text
        else:
            annotated = None
            source_text = combined_c
        if functions is not None:
            name_to_addr = {n: a for n, a in functions}
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))

        address_targets = _addr_targets_of(function_names)
        address_policy = _retdec_address_policy(
            binary_path,
            annotated,
            name_to_addr,
            address_targets,
        )
        binding_index = (
            _retdec_binding_index(annotated, name_to_addr, address_policy)
            if annotated is not None
            else None
        )
        if binding_index is not None and functions is None:
            name_to_addr = _retdec_merge_bindings(name_to_addr, binding_index)

        if function_names:
            normalized_targets = {address_policy.key(address) for address in address_targets}
            name_targets = {value for value in function_names if isinstance(value, str)}
            name_to_addr = {
                name: address
                for name, address in name_to_addr.items()
                if name in name_targets
                or (normalized_targets and address_policy.key(address) in normalized_targets)
            }

        snippets = split_c_functions(source_text) if source_text else {}

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        for name, addr in name_to_addr.items():
            binding_address = address_policy.key(addr)
            if binding_index is not None and (
                name in binding_index.blocked_names
                or binding_address in binding_index.blocked_addresses
            ):
                failed.append(name)
                continue
            annotation = binding_index.by_name.get(name) if binding_index is not None else None
            if annotation is None and binding_index is not None:
                annotation = binding_index.by_address.get(binding_address)
            code = annotation.code if annotation is not None else snippets.get(name)
            if not code:
                failed.append(name)
                continue
            if annotation is not None and annotation.name != name:
                code = re.sub(r"\b" + re.escape(annotation.name) + r"\b", name, code)
            code = self._normalize_code(code)
            decompiled[name] = FunctionDecompilation(
                name=name,
                address=addr,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                line_mappings=list(annotation.line_mappings) if annotation is not None else [],
                variables=_retdec_variables(annotation) if annotation is not None else [],
                metadata=with_variable_occurrence_policy(
                    {
                        "gotos": code.count("goto "),
                        "bools": code.count(" && ") + code.count(" || "),
                    },
                    "exact" if annotation is not None else "unavailable",
                ),
            )

        extra: dict[str, object] = {"via": "docker", "image": self.image}
        if error:
            extra["error"] = error
        if not source_text:
            failed = list(name_to_addr.keys()) or ["all"]

        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=elapsed,
                timeout_occurred=timed_out,
                failed_functions=failed,
                extra=extra,
            ),
            functions=decompiled,
            combined_source=source_text or None,
            output_dir=output_dir,
        )

    def _normalize_code(self, code: str) -> str:
        """Hook for dialect normalization. Default identity."""
        return code


@register_decompiler("retdec")
class RetDecDecompiler(DockerizedDecompiler):
    """RetDec via its annotated JSON token stream in a Docker image.

    Build: ``decbench decompiler-build retdec`` (slow — builds/downloads RetDec).
    """

    name = "retdec"
    display_name = "RetDec"
    image = "decbench/retdec:latest"
    dockerfile = "retdec.Dockerfile"

    def _persist_raw_artifacts(
        self,
        binary_path: Path,
        work_dir: Path,
        output_dir: Path | None,
    ) -> dict[str, object]:
        if os.environ.get(_RETDEC_KEEP_SIDECARS_ENV) != "1":
            return {}
        if output_dir is None:
            raise RuntimeError(f"{_RETDEC_KEEP_SIDECARS_ENV}=1 requires output_dir")
        return _persist_retdec_sidecars(binary_path, work_dir, output_dir)

    def _container_decompile(
        self,
        binary_path: Path,
        work_dir: Path,
    ) -> str | _RetDecAnnotatedSource:
        image_base = raw_common.elf_min_vaddr(binary_path)
        json_proc = self._run_docker(
            args=[
                f"/in/{binary_path.name}",
                "-f",
                "json",
                "-o",
                "/work/out.json",
                "--cleanup",
            ],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_json = work_dir / "out.json"
        if out_json.exists() or out_json.is_symlink():
            try:
                dsm_path = work_dir / "out.dsm"
                dsm = (
                    _read_retdec_regular_text(dsm_path)
                    if dsm_path.exists() or dsm_path.is_symlink()
                    else ""
                )
                instructions, ranges = _retdec_dsm_evidence(dsm, image_base)
                annotated = _parse_retdec_json(
                    _read_retdec_regular_text(out_json),
                    image_base=image_base,
                    valid_instruction_addresses=instructions,
                    function_ranges=ranges,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                _l.warning("retdec JSON provenance unavailable for %s: %s", binary_path, exc)
                if os.environ.get(_RETDEC_KEEP_SIDECARS_ENV) == "1":
                    raise RuntimeError(
                        "RetDec annotated JSON is invalid in raw sidecar retention mode"
                    ) from exc
            else:
                if os.environ.get(_RETDEC_KEEP_SIDECARS_ENV) == "1" and json_proc.returncode != 0:
                    raise RuntimeError(
                        "RetDec annotated JSON invocation failed with "
                        f"exit status {json_proc.returncode}"
                    )
                return annotated

        if os.environ.get(_RETDEC_KEEP_SIDECARS_ENV) == "1":
            raise RuntimeError("RetDec produced no annotated JSON in raw sidecar retention mode")

        proc = self._run_docker(
            args=[f"/in/{binary_path.name}", "-o", "/work/out.c"],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_c = work_dir / "out.c"
        if out_c.is_file():
            return out_c.read_text(errors="replace")
        raise RuntimeError(
            f"retdec produced neither annotated JSON (rc={json_proc.returncode}) nor "
            f"plain C (rc={proc.returncode}): {proc.stderr[-500:] if proc.stderr else ''}"
        )


@register_decompiler("reko")
class RekoDecompiler(DockerizedDecompiler):
    """Reko via a Docker image (.NET CLI ``reko decompile <binary>``).

    Build: ``decbench decompiler-build reko`` (slow — builds Reko via dotnet).
    The image's helper script runs Reko headless and copies the generated
    ``*.c`` to ``/work/out.c``.
    """

    name = "reko"
    display_name = "Reko"
    image = "decbench/reko:latest"
    dockerfile = "reko.Dockerfile"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        raw_override = os.environ.get("DECBENCH_REKO_IMAGE")
        self._image_override = (
            raw_override.strip() if raw_override and raw_override.strip() else None
        )
        self.image = self._image_override or self.image
        self._native_provenance: dict[int, dict[str, Any]] = {}
        self._container_status: dict[str, Any] = {}
        self._container_error: str | None = None
        self._architecture_mode = "auto"
        self._architecture_evidence = "uninspected"

    def _configure_requested_version(self) -> None:
        if self._image_override is not None:
            self.image = self._image_override
            return
        super()._configure_requested_version()

    def _container_decompile(self, binary_path: Path, work_dir: Path) -> str:
        self._native_provenance = {}
        self._container_status = {}
        self._container_error = None
        self._architecture_mode, self._architecture_evidence = _reko_architecture_mode(binary_path)
        proc = self._run_docker(
            args=[
                f"/in/{binary_path.name}",
                "/work/out.c",
                "/work/native-provenance.json",
                self._architecture_mode,
            ],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_c = work_dir / "out.c"
        self._container_status = _load_reko_status(work_dir / "reko-status.json")
        log_tail = _reko_log_tail(work_dir / "reko.log")
        cli_failed = self._container_status.get("cli_succeeded") is False
        status_mode = self._container_status.get("mode")
        mode_mismatch = bool(self._container_status) and status_mode != self._architecture_mode
        if proc.returncode != 0 or cli_failed or mode_mismatch:
            details = [f"container rc={proc.returncode}"]
            if self._container_status:
                details.append(
                    "primary rc="
                    f"{self._container_status.get('primary_returncode')}, legacy rc="
                    f"{self._container_status.get('legacy_returncode')}"
                )
            if mode_mismatch:
                details.append(
                    f"status mode={status_mode!r}, requested mode={self._architecture_mode!r}"
                )
            diagnostic = log_tail or (proc.stderr[-500:] if proc.stderr else "")
            if diagnostic:
                details.append(diagnostic)
            self._container_error = "reko container failure: " + "; ".join(details)
        if out_c.is_file():
            self._native_provenance = _load_reko_provenance(work_dir / "native-provenance.json")
            return out_c.read_text(errors="replace")
        raise RuntimeError(
            self._container_error
            or (
                f"reko produced no out.c (rc={proc.returncode}): "
                f"{proc.stderr[-500:] if proc.stderr else ''}"
            )
        )

    def _build_result(
        self,
        binary_path: Path,
        combined_c: str | _RetDecAnnotatedSource,
        functions: list[tuple[str, int]] | None,
        function_names: set[int] | set[str] | None,
        elapsed: float,
        timed_out: bool,
        error: str | None,
        output_dir: Path | None,
    ) -> DecompilationResult:
        """Bind Reko's stripped names and native variables by exact entry address."""
        if isinstance(combined_c, _RetDecAnnotatedSource):
            combined_c = combined_c.text
        address_targets = {address & ~1 for address in _addr_targets_of(function_names)}
        if functions is not None:
            name_to_addr = {name: address for name, address in functions}
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))
            for name, address in _reko_target_bindings(
                self._native_provenance, address_targets
            ).items():
                name_to_addr.setdefault(name, address)

        if function_names:
            name_targets = {value for value in function_names if isinstance(value, str)}
            name_to_addr = {
                name: address
                for name, address in name_to_addr.items()
                if name in name_targets
                or (address_targets and raw_common._addr_matches(address, address_targets))
            }

        snippets = split_c_functions(self._normalize_code(combined_c)) if combined_c else {}
        executable_regions = _reko_executable_regions(binary_path)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        native_variables = 0
        for name, address in name_to_addr.items():
            record = _reko_record_at(self._native_provenance, address)
            reko_name = str(record.get("name") or "") if record else ""
            code = snippets.get(reko_name) if reko_name else None
            if not code:
                code = snippets.get(name)
            if not code:
                failed.append(name)
                continue
            code = self._normalize_code(code)
            code_identifier = _func_ident_in_code(code)
            if code_identifier and code_identifier != name:
                code = re.sub(r"\b" + re.escape(code_identifier) + r"\b", name, code)
            variables = _reko_variables_from_code(
                code,
                name,
                record,
                executable_regions,
            )
            native_variables += sum(bool(variable.addresses) for variable in variables)
            decompiled[name] = FunctionDecompilation(
                name=name,
                address=address,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                line_mappings=[],
                variables=variables,
                metadata=with_variable_occurrence_policy(
                    raw_common.extract_metrics(code), "direct"
                ),
            )

        extra: dict[str, object] = {
            "via": "docker",
            "image": self.image,
            "architecture_mode": self._architecture_mode,
            "architecture_evidence": self._architecture_evidence,
            "container_status": self._container_status,
            "native_provenance_schema": _REKO_PROVENANCE_SCHEMA,
            "native_provenance_functions": len(self._native_provenance),
            "native_provenance_variables": native_variables,
        }
        native_matched_targets = {
            address
            for address in address_targets
            if _reko_record_at(self._native_provenance, address) is not None
        }
        returned_addresses = {
            function.address & ~1
            for function in decompiled.values()
            if function.address is not None
        }
        returned_matched_targets = address_targets & returned_addresses
        if address_targets:
            if len(returned_matched_targets) == len(address_targets):
                target_match_status = "complete"
            elif returned_matched_targets:
                target_match_status = "partial"
            else:
                target_match_status = "none"
        else:
            target_match_status = "not_requested"
        extra.update(
            {
                "requested_target_addresses": len(address_targets),
                "native_target_matches": len(native_matched_targets),
                "returned_target_matches": len(returned_matched_targets),
                "target_match_status": target_match_status,
            }
        )
        errors = [message for message in (error, self._container_error) if message]
        if address_targets and not returned_matched_targets:
            errors.append(f"reko recovered 0 of {len(address_targets)} requested target addresses")
            failed = ["all"]
        if errors:
            extra["error"] = "; ".join(dict.fromkeys(errors))
        if not combined_c:
            failed = list(name_to_addr.keys()) or ["all"]

        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=elapsed,
                timeout_occurred=timed_out,
                failed_functions=failed,
                extra=extra,
            ),
            functions=decompiled,
            combined_source=combined_c or None,
            output_dir=output_dir,
        )

    def _normalize_code(self, code: str) -> str:
        return _normalize_reko_dialect(code)


_REKO_PROVENANCE_SCHEMA = "decbench-reko-native-provenance-v1"
_REKO_STATUS_SCHEMA = "decbench-reko-status-v1"
_REKO_DEFINE_HEADER_RE = re.compile(r"(?m)^([ \t]*)define[ \t]+([A-Za-z_]\w*)[ \t]*$")
_REKO_PERCENT_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:struct|union)[ \t]+[A-Za-z_]\w*[ \t]*\*?"
    r"|[A-Za-z_]\w*[ \t]*\*?)[ \t]+%([A-Za-z_]\w*)\b"
)


def _reko_code_view(source: str) -> str:
    """Return source with C literals and comments hidden but offsets preserved."""
    view = list(source)
    state = "code"
    quote = ""
    index = 0

    def hide(position: int) -> None:
        if view[position] != "\n":
            view[position] = " "

    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                hide(index)
                hide(index + 1)
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                hide(index)
                hide(index + 1)
                index += 2
                state = "block_comment"
                continue
            if current in {'"', "'"}:
                quote = current
                hide(index)
                index += 1
                state = "literal"
                continue
            index += 1
            continue
        if state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                hide(index)
            index += 1
            continue
        if state == "block_comment":
            hide(index)
            if current == "*" and following == "/":
                hide(index + 1)
                index += 2
                state = "code"
            else:
                index += 1
            continue
        hide(index)
        if current == "\\" and following:
            hide(index + 1)
            index += 2
        else:
            index += 1
            if current == quote:
                state = "code"

    return "".join(view)


def _normalize_reko_dialect(source: str) -> str:
    """Normalize Reko declarations without rewriting valid C tokens."""
    code_view = _reko_code_view(source)
    replacements = [
        (match.start(), match.end(), f"{match.group(1)}void {match.group(2)}(void)")
        for match in _REKO_DEFINE_HEADER_RE.finditer(code_view)
    ]
    for start, end, replacement in reversed(replacements):
        source = source[:start] + replacement + source[end:]

    code_view = _reko_code_view(source)
    percent_names = {match.group(1) for match in _REKO_PERCENT_DECL_RE.finditer(code_view)}
    if not percent_names:
        return source

    normalized: list[str] = []
    index = 0
    while index < len(source):
        if code_view[index] != "%":
            normalized.append(source[index])
            index += 1
            continue
        match = re.match(r"%([A-Za-z_]\w*)", code_view[index:])
        if match is None or match.group(1) not in percent_names:
            normalized.append(source[index])
            index += 1
            continue
        normalized.append(match.group(1))
        index += len(match.group(0))
    return "".join(normalized)


def _reko_architecture_mode(binary_path: Path) -> tuple[str, str]:
    """Choose Reko's ARM decode mode from ELF entry and profile evidence."""
    info = binfmt.detect(binary_path)
    if info is None or info.fmt != "elf" or info.arch != "arm":
        return "auto", "default"
    try:
        from elftools.elf.elffile import ELFFile

        with binary_path.open("rb") as stream:
            entry = int(ELFFile(stream).header["e_entry"])
    except Exception:  # noqa: BLE001
        return "auto", "elf-arm-unreadable-entry"
    if entry & 1:
        return "auto", "elf-arm-entry-thumb-bit"
    if binfmt.elf_is_arm_mclass(binary_path):
        return "thumb", "elf-arm-attributes-m-profile"
    return "auto", "elf-arm-default"


def _load_reko_status(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != _REKO_STATUS_SCHEMA:
        return {}
    return payload


def _reko_log_tail(path: Path, limit: int = 500) -> str:
    try:
        return path.read_text(errors="replace")[-limit:].strip()
    except OSError:
        return ""


def _reko_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed >= 0 else None


def _load_reko_provenance(path: Path) -> dict[int, dict[str, Any]]:
    """Load an exact-identity Reko sidecar, dropping every ambiguous record."""
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != _REKO_PROVENANCE_SCHEMA:
        return {}
    records: dict[int, dict[str, Any]] = {}
    duplicate_addresses: set[int] = set()
    raw_functions = payload.get("functions")
    if not isinstance(raw_functions, list):
        return {}
    for raw_record in raw_functions:
        if not isinstance(raw_record, dict):
            continue
        address = _reko_int(raw_record.get("address"))
        name = str(raw_record.get("name") or "")
        if address is None or not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        variables: dict[str, list[int]] = {}
        duplicate_names: set[str] = set()
        raw_variables = raw_record.get("variables")
        if not isinstance(raw_variables, list):
            raw_variables = []
        for raw_variable in raw_variables:
            if not isinstance(raw_variable, dict):
                continue
            variable_name = str(raw_variable.get("name") or "")
            if not re.fullmatch(r"[A-Za-z_]\w*", variable_name):
                continue
            if variable_name in variables:
                duplicate_names.add(variable_name)
                continue
            raw_addresses = raw_variable.get("addresses")
            if not isinstance(raw_addresses, list):
                continue
            variables[variable_name] = sorted(
                {parsed for value in raw_addresses if (parsed := _reko_int(value)) is not None}
            )
        for duplicate in duplicate_names:
            variables.pop(duplicate, None)
        record = {"name": name, "address": address, "variables": variables}
        if address in records:
            duplicate_addresses.add(address)
        else:
            records[address] = record
    for duplicate_address in duplicate_addresses:
        records.pop(duplicate_address, None)
    return records


def _reko_record_at(provenance: dict[int, dict[str, Any]], address: int) -> dict[str, Any] | None:
    matches = [
        record
        for record_address, record in provenance.items()
        if raw_common._addr_matches(address, {record_address})
    ]
    return matches[0] if len(matches) == 1 else None


def _reko_target_bindings(
    provenance: dict[int, dict[str, Any]], address_targets: set[int]
) -> dict[str, int]:
    """Bind requested stripped-binary entries to unique final Reko names."""
    candidates: dict[str, list[int]] = {}
    for address in sorted({target & ~1 for target in address_targets}):
        record = _reko_record_at(provenance, address)
        name = str(record.get("name") or "") if record else ""
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            candidates.setdefault(name, []).append(address)
    return {name: addresses[0] for name, addresses in candidates.items() if len(addresses) == 1}


def _reko_executable_regions(binary_path: Path) -> tuple[tuple[int, int], ...]:
    try:
        from decbench.utils.binfmt import executable_regions

        return tuple((start, start + len(data)) for start, data in executable_regions(binary_path))
    except Exception:  # noqa: BLE001
        return ()


def _reko_variables_from_code(
    code: str,
    function_name: str,
    record: dict[str, Any] | None,
    executable_regions: tuple[tuple[int, int], ...],
) -> list[VariableInfo]:
    """Parse every rendered variable, then attach only verified native addresses."""
    try:
        from decbench.metrics.type_match import parse_c_variables

        variables = parse_c_variables(code, function_name)
    except Exception:  # noqa: BLE001
        return []
    evidence = record.get("variables", {}) if record else {}
    name_counts: dict[str, int] = {}
    for variable in variables:
        if variable.name:
            name_counts[variable.name] = name_counts.get(variable.name, 0) + 1
    out: list[VariableInfo] = []
    for variable in variables:
        addresses: list[int] = []
        if variable.name and name_counts.get(variable.name) == 1:
            addresses = sorted(
                {
                    address
                    for address in evidence.get(variable.name, [])
                    if any(start <= address < end for start, end in executable_regions)
                }
            )
        out.append(variable.model_copy(update={"addresses": addresses}))
    return out


_R2_ENTRY_NAMES = frozenset({"entry0", "entry1", "entry.init0", "entry.fini0", "entry.preinit0"})

_C_KEYWORDS = frozenset({"if", "while", "for", "switch", "return", "do", "else", "sizeof", "case"})

# Tolerates both r2 pseudo-name spellings (``fcn.00003bed`` from ``pdc`` and
# ``fcn_00003bed`` from ``pdd``). The parameter list is matched non-greedily so
# an ``ident (...)`` inside a comment cannot swallow text up to the real ``) {``.
_R2_DEF_RE = re.compile(r"\b([A-Za-z_][\w.]*)\s*\([^;{}]*?\)\s*\{")
_R2_DRIVER_SCHEMA_VERSION = 1
_R2_DRIVER_CONTAINER_PATH = "/opt/r2dec-decompile.py"


def _r2_int(value: Any, default: int | None = None) -> int | None:
    """Best-effort integer conversion for radare2's mixed JSON scalars."""
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _r2_json_lines(payload: Any) -> tuple[str, list[dict[str, Any]]] | None:
    """Turn r2dec ``pddj`` rows into code and same-render line evidence."""
    rows = payload.get("lines") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        return None

    rendered: list[tuple[str, int | None]] = []
    for row in rows:
        if not isinstance(row, dict) or "str" not in row:
            continue
        text = str(row.get("str") or "")
        pieces = text.splitlines() or [""]
        offset = _r2_int(row.get("offset"))
        rendered.extend((piece, offset) for piece in pieces)
    if not rendered:
        return None

    while rendered and not rendered[0][0].strip():
        rendered.pop(0)
    while rendered and not rendered[-1][0].strip():
        rendered.pop()
    if not rendered:
        return None

    code = "\n".join(text for text, _offset in rendered)
    mappings = [
        {"line_number": line_number, "addresses": [offset]}
        for line_number, (_text, offset) in enumerate(rendered, 1)
        if offset is not None
    ]
    return code, mappings


def _r2_json_annotations(payload: Any) -> tuple[str, list[dict[str, Any]]] | None:
    """Turn radare2 ``pdcj`` code annotations into per-line offsets."""
    if not isinstance(payload, dict):
        return None
    raw_code = str(payload.get("code") or "")
    code = raw_code.strip()
    annotations = payload.get("annotations")
    if not code or not isinstance(annotations, list):
        return None
    code_start = raw_code.find(code)
    mappings: list[dict[str, Any]] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        offset = _r2_int(annotation.get("offset"))
        position = _r2_int(annotation.get("start"))
        if offset is None or position is None or position < code_start:
            continue
        adjusted = min(position - code_start, len(code))
        mappings.append(
            {
                "line_number": code.count("\n", 0, adjusted) + 1,
                "addresses": [offset],
            }
        )
    return code, mappings


def _r2_cmdj(r: Any, command: str, default: Any) -> Any:
    """Run one JSON command without letting optional provenance break output."""
    try:
        payload = r.cmdj(command)
    except Exception:  # noqa: BLE001
        return default
    return default if payload is None else payload


def _r2_variable_records(
    r: Any,
    addr: int,
    line_mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect r2's variable metadata and read/write instruction addresses."""
    metadata = _r2_cmdj(r, f"afvj @ {addr}", {})
    if not isinstance(metadata, dict):
        return []

    accesses: dict[str, set[int]] = {}
    for command in ("afvRj", "afvWj"):
        records = _r2_cmdj(r, f"{command} @ {addr}", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if not name:
                continue
            for value in record.get("addrs") or []:
                address = _r2_int(value)
                if address is not None:
                    accesses.setdefault(name, set()).add(address)

    signature = _r2_cmdj(r, f"afcfj @ {addr}", [])
    signature_args: list[str] = []
    if isinstance(signature, list) and signature and isinstance(signature[0], dict):
        signature_args = [
            str(arg.get("name") or "")
            for arg in signature[0].get("args") or []
            if isinstance(arg, dict) and arg.get("name")
        ]
    lines_by_address: dict[int, set[int]] = {}
    for mapping in line_mappings:
        line_number = _r2_int(mapping.get("line_number"))
        if line_number is None:
            continue
        for value in mapping.get("addresses") or []:
            address = _r2_int(value)
            if address is not None:
                lines_by_address.setdefault(address, set()).add(line_number)

    ordered: list[tuple[str, dict[str, Any]]] = []
    for group in ("reg", "sp", "bp"):
        records = metadata.get(group) or []
        if not isinstance(records, list):
            continue
        ordered.extend((group, record) for record in records if isinstance(record, dict))

    fallback_args = list(
        dict.fromkeys(
            str(record.get("name") or "")
            for group, record in ordered
            if (group == "reg" or str(record.get("kind") or "") == "arg") and record.get("name")
        )
    )
    signature_positions = {name: index for index, name in enumerate(signature_args)}
    arg_positions = {
        name: signature_positions.get(name, index) for index, name in enumerate(fallback_args)
    }

    variables: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for group, record in ordered:
        name = str(record.get("name") or "")
        if not name:
            continue
        ref = record.get("ref")
        stack_offset = _r2_int(ref.get("offset")) if isinstance(ref, dict) else None
        identity = (group, name, stack_offset)
        if identity in seen:
            continue
        seen.add(identity)
        raw_addresses = sorted(accesses.get(name, set()))
        is_arg = name in arg_positions
        variables.append(
            {
                "name": name,
                "type": str(record.get("type") or ""),
                "stack_offset": stack_offset,
                "size": _r2_int(record.get("size")),
                "kind": "arg" if is_arg else "stack",
                "arg_index": arg_positions.get(name),
                "line_numbers": sorted(
                    {
                        line_number
                        for address in raw_addresses
                        for line_number in lines_by_address.get(address, set())
                    }
                ),
                "addresses": raw_addresses,
            }
        )
    return variables


def _r2_inferred_variables(
    code: str,
    function_name: str,
    line_mappings: list[Any],
) -> list[VariableInfo]:
    """Join uniquely bound C variables to native r2 render-line addresses."""
    try:
        from decbench.metrics.type_match import parse_c_variables
        from decbench.metrics.variable_features import variable_occurrence_lines

        variables = parse_c_variables(code, function_name)
        occurrence_lines = variable_occurrence_lines(
            code,
            function_name,
            (variable.name for variable in variables),
            require_exact_function_name=True,
        )
    except Exception:  # noqa: BLE001
        return []
    line_addresses = {
        int(mapping.line_number): {int(address) for address in mapping.addresses}
        for mapping in line_mappings
    }
    out: list[VariableInfo] = []
    for variable in variables:
        lines = list(occurrence_lines.get(variable.name, ())) if variable.name else []
        out.append(
            variable.model_copy(
                update={
                    "line_numbers": lines,
                    "addresses": sorted(
                        {
                            address
                            for line_number in lines
                            for address in line_addresses.get(line_number, set())
                        }
                    ),
                }
            )
        )
    return out


def _r2_is_import(name: str) -> bool:
    """Whether an r2 function flag names an import / PLT / reloc stub."""
    return (
        name.startswith("sym.imp.")
        or name.startswith("imp.")
        or name.startswith("reloc.")
        or ".imp." in name
    )


def _r2_bare_name(name: str) -> str:
    """Strip r2's flag namespace (``sym.``/``fcn.``/``loc.``) to a bare ident."""
    return name.rsplit(".", 1)[-1] if name else name


#: Back-compat alias; the driver's address filter is parsed in ``raw.common``.
_addr_targets_of = raw_common.addr_targets_of


def _skip_r2_function(
    bare_name: str,
    file_addr: int,
    code_ranges: raw_common.CodeRangeFilter,
    addr_targets: set[int] | None = None,
) -> bool:
    """Whether to drop an r2-discovered function outside executable code.

    A function whose address is one the driver asked for is a VERIFIED real
    function and is kept whatever section it landed in; the exemption now lives
    in the shared filter, so every backend applies it identically.
    """

    return raw_common.should_skip_function(bare_name, file_addr, code_ranges, addr_targets)


def _func_ident_in_code(code: str) -> str | None:
    """The identifier of the first top-level function definition in ``code``.

    Block comments (``/* ... */`` — r2dec prefixes its output with a
    ``/* r2dec pseudo code output ... */`` banner), line comments, and
    preprocessor lines (r2dec emits ``#include`` / ``#define`` macros) are
    stripped first so none of them is mistaken for the signature, and C keywords
    are skipped so a leading ``if (...) {`` is not either. Returns ``None`` when
    no definition opener is found.
    """
    stripped = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    stripped = re.sub(r"//.*", "", stripped)
    stripped = re.sub(r"(?m)^[ \t]*#.*$", "", stripped)
    for m in _R2_DEF_RE.finditer(stripped):
        ident = m.group(1)
        if ident not in _C_KEYWORDS:
            return ident
    return None


@register_decompiler("r2dec")
class R2DecDecompiler(DockerizedDecompiler):
    """radare2's r2dec decompiler (address-keyed, stripped-binary ready).

    Function discovery comes from radare2's OWN analysis (``aaa`` + ``aflj``),
    not the ELF symbol table, so it works on fully STRIPPED ELF/PE and on ARM
    firmware. Each function's start is normalized to ELF-file space
    (``r2_addr - r2_baddr + elf_min_vaddr``) so it matches DWARF ``low_pc`` and
    the benchmark driver's address-based function filter — radare2 loads a binary
    at its own ``baddr`` (the ELF min PT_LOAD vaddr / PE ImageBase), which equals
    ``elf_min_vaddr``, so an r2 function address is already ELF-file space.

    Three execution paths, tried in this order:

    1. **native pdd** — radare2 + the r2dec plugin installed on the host;
    2. **docker pdd** — the ``decbench/r2dec`` image (real r2dec built from
       source; the host's packaged r2 usually lacks the dev headers to build the
       plugin natively);
    3. **native pdc** — radare2's built-in pseudo-decompiler (always available
       when r2 is installed, but its asm-like output rarely parses for GED).

    The ``function_names`` filter accepts a set of **ints** (ELF-file-space
    addresses — the benchmark driver's DWARF ``low_pc`` set, matched Thumb-bit
    tolerant) or a set of **strs** (legacy name matching).
    """

    name = "r2dec"
    display_name = "r2dec"
    image = "decbench/r2dec:latest"
    dockerfile = "r2dec.Dockerfile"

    _R2_FLAGS = ["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"]

    @staticmethod
    def _native_available() -> bool:
        if shutil.which("r2") is None and shutil.which("radare2") is None:
            return False
        try:
            import r2pipe  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    def _native_plugin_available() -> bool:
        """True iff radare2's r2dec plugin (``pdd``) is installed natively.

        Scans the user + system radare2 plugin dirs for the r2dec core plugin
        (``*pdd*`` / ``*r2dec*``) so the real decompiler can be preferred over the
        built-in ``pdc`` without opening r2. A false negative is harmless: the
        native path's command probe still upgrades to ``pdd`` if it is present.
        """
        dirs = [os.path.expanduser("~/.local/share/radare2/plugins")]
        try:
            proc = subprocess.run(
                [shutil.which("r2") or "radare2", "-H", "R2_LIBR_PLUGINS"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            sysdir = (proc.stdout or "").strip()
            if sysdir:
                dirs.append(sysdir)
        except Exception:  # noqa: BLE001
            dirs.extend(["/usr/lib/radare2", "/usr/local/lib/radare2"])
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            for pat in ("*pdd*", "*r2dec*"):
                if glob.glob(os.path.join(d, "**", pat), recursive=True):
                    return True
        return False

    def is_available(self) -> bool:
        """Require an explicitly configured image; otherwise allow native r2."""
        if self._version_image_configured:
            return self._image_present(self.image)
        return self._native_available() or self._image_present(self.image)

    def _select_path(self) -> str:
        """Choose the execution path: ``"native"`` or ``"docker"``.

        A configured image is an explicit Docker pin. Otherwise, preference is
        native-with-plugin (real r2dec, no container overhead) > docker (real
        r2dec in a container) > native-without-plugin (``pdc``). The native path
        probes ``pdd``/``pdc`` itself, so this only decides host vs container.
        """
        if self._version_image_configured:
            return "docker"
        native = self._native_available()
        if native and self._native_plugin_available():
            return "native"
        if self._image_present(self.image):
            return "docker"
        if native:
            return "native"
        return "docker"

    def _version_for_path(self, path: str) -> str | None:
        if path == "native":
            try:
                proc = subprocess.run(
                    [shutil.which("r2") or "radare2", "-v"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=20,
                )
                first = proc.stdout.splitlines()[0] if proc.stdout else ""
                m = re.search(r"radare2\s+(\S+)", first)
                if m:
                    return f"r2-{m.group(1)}"
            except Exception:  # noqa: BLE001
                pass
            return "native"
        return super().get_version()

    def get_version(self) -> str | None:
        return self._version_for_path(self._select_path())

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary via the real r2dec (native or docker) or ``pdc``."""
        if self._select_path() == "docker":
            return self._decompile_docker(
                binary_path, functions, output_dir, function_names, progress_path
            )
        return self._decompile_native(
            binary_path, functions, output_dir, function_names, progress_path
        )

    @staticmethod
    def _discover(
        r: Any,
        elf_base: int,
        code_ranges: raw_common.CodeRangeFilter,
        baddr: int,
        addr_targets: set[int] | None = None,
    ) -> list[tuple[str, int, int]]:
        """``(r2_flag_name, file_addr, r2_addr)`` for benchmarkable functions.

        Uses radare2's ``aflj`` (function list). ``file_addr`` is ELF-file space
        (``r2_addr - baddr + elf_base``). Imports/PLT/reloc stubs, the entrypoint
        alias, CRT helpers, and anything outside a file-backed executable
        section are dropped.
        """
        funcs = r.cmdj("aflj") or []
        out: list[tuple[str, int, int]] = []
        for fn in funcs:
            name = fn.get("name") or ""
            raw = fn.get("addr")
            if raw is None:
                raw = fn.get("offset")
            if not name or raw is None:
                continue
            if _r2_is_import(name) or name in _R2_ENTRY_NAMES:
                continue
            raw = int(raw)
            file_addr = raw - baddr + elf_base
            if _skip_r2_function(_r2_bare_name(name), file_addr, code_ranges, addr_targets):
                continue
            out.append((name, file_addr, raw))
        out.sort(key=lambda t: t[1])
        return out

    @staticmethod
    def _narrow(
        discovered: list[tuple[str, int, int]],
        function_names: set[int] | set[str] | None,
        binary_name: str,
    ) -> list[tuple[str | None, int, int, str]]:
        """Restrict discovered functions to the requested set.

        ``function_names`` may hold ELF-file-space ADDRESSES (ints — the driver's
        DWARF ``low_pc`` filter, matched Thumb-bit tolerant) or NAMES (strs,
        legacy). Returns ``(label, file_addr, r2_addr, r2_flag)`` tuples where
        ``label`` is the requested name for the str path (so the result keys by
        it) and ``None`` otherwise (the code identifier becomes the key). An
        explicit filter is fail-closed, so a mismatch yields an empty result
        instead of broadening the requested benchmark subset.
        """
        all_targets: list[tuple[str | None, int, int, str]] = [
            (None, fa, raw, nm) for (nm, fa, raw) in discovered
        ]
        if not function_names:
            return all_targets
        addr_targets = {
            int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)
        }
        name_targets = {str(x) for x in function_names if isinstance(x, str)}
        if addr_targets:
            kept: list[tuple[str | None, int, int, str]] = [
                (None, fa, raw, nm)
                for (nm, fa, raw) in discovered
                if raw_common._addr_matches(fa, addr_targets)
            ]
            if kept:
                _l.debug(
                    "r2dec: narrowed %d/%d functions to source set for %s",
                    len(kept),
                    len(discovered),
                    binary_name,
                )
            else:
                _l.warning(
                    "r2dec: no discovered address matched the requested source set for %s",
                    binary_name,
                )
            return kept
        if name_targets:
            named: list[tuple[str | None, int, int, str]] = []
            for nm, fa, raw in discovered:
                bare = _r2_bare_name(nm)
                match = nm if nm in name_targets else (bare if bare in name_targets else None)
                if match is not None:
                    named.append((match, fa, raw, nm))
            return named
        return []

    @staticmethod
    def _make_function(
        r2_flag: str,
        file_addr: int,
        code: str,
        label: str | None,
        provenance: dict[str, Any] | None = None,
        *,
        r2_addr: int | None = None,
        baddr: int = 0,
        elf_base: int = 0,
    ) -> FunctionDecompilation | None:
        """Build a :class:`FunctionDecompilation`, keeping ``.name`` equal to the
        identifier that appears in ``decompiled_code``.

        The run driver relabels a stripped-binary decompilation by address,
        rewriting ``fd.name`` in BOTH the code and the function key to the DWARF
        name — which only works if ``fd.name`` is the identifier actually used in
        the code. So we adopt the code's own identifier (or, on the legacy name
        path, rewrite the code to the requested ``label``).
        """
        code = (code or "").strip()
        if not code:
            return None
        provenance = provenance or {}
        function_raw = _r2_int(r2_addr, _r2_int(provenance.get("addr"), file_addr))
        function_size = _r2_int(provenance.get("size"), 0) or 0
        is_thumb = bool(provenance.get("is_thumb"))
        normalized_start = (
            (function_raw & ~1) if is_thumb and function_raw is not None else function_raw
        )

        def _evidence_address(value: Any) -> int | None:
            raw_address = _r2_int(value)
            if raw_address is None:
                return None
            normalized = raw_address & ~1 if is_thumb else raw_address
            if normalized_start is not None and normalized < normalized_start:
                return None
            if (
                function_size > 0
                and normalized_start is not None
                and normalized >= normalized_start + function_size
            ):
                return None
            return normalized - baddr + elf_base

        code_ident = _func_ident_in_code(code)
        final = label or code_ident or r2_flag
        if code_ident and code_ident != final:
            code = re.sub(r"\b" + re.escape(code_ident) + r"\b", final, code)
        line_count = code.count("\n") + 1
        line_to_addresses: dict[int, set[int]] = {}
        for mapping in provenance.get("line_mappings") or []:
            if not isinstance(mapping, dict):
                continue
            line_number = _r2_int(mapping.get("line_number"), 0) or 0
            if not 1 <= line_number <= line_count:
                continue
            for value in mapping.get("addresses") or []:
                address = _evidence_address(value)
                if address is not None:
                    line_to_addresses.setdefault(line_number, set()).add(address)
        line_mappings = raw_common.merge_line_addresses(line_to_addresses)

        variables: list[VariableInfo] = []
        for record in provenance.get("variables") or []:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if not name:
                continue
            line_numbers = sorted(
                {
                    line_number
                    for value in record.get("line_numbers") or []
                    if 1 <= (line_number := (_r2_int(value, 0) or 0)) <= line_count
                }
            )
            addresses = sorted(
                {
                    address
                    for value in record.get("addresses") or []
                    if (address := _evidence_address(value)) is not None
                }
            )
            raw_size = _r2_int(record.get("size"))
            size = raw_size if raw_size is not None and raw_size > 0 else None
            raw_arg_index = _r2_int(record.get("arg_index"))
            arg_index = raw_arg_index if raw_arg_index is not None and raw_arg_index >= 0 else None
            kind = "arg" if record.get("kind") == "arg" else "stack"
            variables.append(
                VariableInfo(
                    name=name,
                    type=str(record.get("type") or ""),
                    stack_offset=_r2_int(record.get("stack_offset")),
                    size=size,
                    kind=kind,
                    arg_index=arg_index if kind == "arg" else None,
                    line_numbers=line_numbers,
                    addresses=addresses,
                )
            )
        occurrence_policy: VariableOccurrencePolicy = "unavailable"
        if variables:
            occurrence_policy = "direct"
        elif line_mappings:
            variables = _r2_inferred_variables(code, final, line_mappings)
            occurrence_policy = "exact"
        output_address = file_addr & ~1 if is_thumb else file_addr
        return FunctionDecompilation(
            name=final,
            address=output_address,
            decompiled_code=code,
            line_count=line_count,
            line_mappings=line_mappings,
            variables=variables,
            metadata=with_variable_occurrence_policy(
                raw_common.extract_metrics(code), occurrence_policy
            ),
        )

    def _make_result(
        self,
        binary_path: Path,
        decompiled: dict[str, FunctionDecompilation],
        failed: list[str],
        elapsed: float,
        via: str,
        cmd: str,
        output_dir: Path | None,
        *,
        partial: bool = False,
        timed_out: bool = False,
        error: str | None = None,
    ) -> DecompilationResult:
        extra: dict[str, Any] = {"via": via, "command": cmd}
        if via == "docker":
            extra["image"] = self.image
        if partial:
            extra["partial"] = True
        if error:
            extra["error"] = error
        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self._version_for_path(via),
                total_time_seconds=elapsed,
                timeout_occurred=timed_out,
                failed_functions=list(failed),
                extra=extra,
            ),
            functions=dict(decompiled),
            output_dir=output_dir,
        )

    def _write_artifacts(
        self,
        result: DecompilationResult,
        output_dir: Path | None,
        binary_path: Path,
    ) -> None:
        if output_dir is None:
            return
        output_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(Exception):
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
        with contextlib.suppress(Exception):
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

    def _decompile_native(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        output_dir: Path | None,
        function_names: set[int] | set[str] | None,
        progress_path: Path | None,
    ) -> DecompilationResult:
        import r2pipe

        start = time.time()
        elf_base = raw_common.elf_min_vaddr(binary_path)
        code_ranges = raw_common.executable_code_ranges(binary_path)
        r2_addr_targets = _addr_targets_of(function_names)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        used_cmd = "pdc"
        targets: list[tuple[str | None, int, int, str]] = []

        def _dump() -> None:
            common_res = self._make_result(
                binary_path,
                decompiled,
                failed,
                time.time() - start,
                "native",
                used_cmd,
                output_dir,
                partial=True,
            )
            raw_common.dump_progress(progress_path, common_res)

        r = None
        try:
            r = r2pipe.open(str(binary_path), flags=self._R2_FLAGS)
            r.cmd("aaa")
            baddr = self._r2_baddr(r)
            used_cmd = self._probe_decompile_cmd(r)
            if functions is not None:
                for name, fa in functions:
                    raw = int(fa) - elf_base + baddr
                    with contextlib.suppress(Exception):
                        r.cmd(f"af @ {raw}")
                    targets.append((name, int(fa), raw, name))
            else:
                targets = self._narrow(
                    self._discover(r, elf_base, code_ranges, baddr, r2_addr_targets),
                    function_names,
                    binary_path.name,
                )
            for label, file_addr, raw, r2_flag in targets:
                try:
                    provenance = self._decompile_one_native(r, used_cmd, raw)
                except Exception as e:  # noqa: BLE001
                    _l.debug("r2dec failed on %s@%#x: %s", r2_flag, raw, e)
                    provenance = None
                fd = self._make_function(
                    r2_flag,
                    file_addr,
                    str((provenance or {}).get("code") or ""),
                    label,
                    provenance,
                    r2_addr=raw,
                    baddr=baddr,
                    elf_base=elf_base,
                )
                if fd is None:
                    failed.append(label or _r2_bare_name(r2_flag))
                else:
                    decompiled[fd.name] = fd
                _dump()
        except Exception as e:  # noqa: BLE001
            _l.error("r2dec native run failed on %s: %s", binary_path, e)
            if not decompiled:
                failed = [t[0] or _r2_bare_name(t[3]) for t in targets] or ["all"]
        finally:
            if r is not None:
                with contextlib.suppress(Exception):
                    r.quit()

        result = self._make_result(
            binary_path, decompiled, failed, time.time() - start, "native", used_cmd, output_dir
        )
        self._write_artifacts(result, output_dir, binary_path)
        return result

    def _decompile_docker(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        output_dir: Path | None,
        function_names: set[int] | set[str] | None,
        progress_path: Path | None,
    ) -> DecompilationResult:
        if not self._image_present(self.image):
            raise RuntimeError(
                f"Decompiler '{self.name}' docker image '{self.image}' missing — "
                f"run `decbench decompiler-build {self.id}`"
            )
        start = time.time()
        elf_base = raw_common.elf_min_vaddr(binary_path)
        code_ranges = raw_common.executable_code_ranges(binary_path)
        r2_addr_targets = _addr_targets_of(function_names)

        addr_targets: list[int] | None = None
        ints: set[int] = set()
        if function_names:
            ints |= {
                int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)
            }
        if functions:
            ints |= {int(a) for (_n, a) in functions}
        if ints:
            addr_targets = sorted(ints)

        entries: list[dict[str, Any]] = []
        used_cmd = "pdd"
        error: str | None = None
        timed_out = False
        with tempfile.TemporaryDirectory(prefix=f"decbench_{self.name}_") as td:
            work_dir = Path(td)
            targets_arg = "NONE"
            if addr_targets is not None:
                (work_dir / "targets.json").write_text(json.dumps(addr_targets))
                targets_arg = "/work/targets.json"
            try:
                proc = self._run_docker(
                    args=[f"/in/{binary_path.name}", "/work/out.json", targets_arg],
                    binary_path=binary_path,
                    work_dir=work_dir,
                    readonly_mounts=[
                        (_DOCKER_DIR / "r2dec-decompile.py", _R2_DRIVER_CONTAINER_PATH)
                    ],
                )
                out_json = work_dir / "out.json"
                if out_json.is_file():
                    payload = json.loads(out_json.read_text() or "{}")
                    if not isinstance(payload, dict):
                        raise RuntimeError("r2dec container returned a legacy driver payload")
                    schema_version = payload.get("schema_version")
                    if (
                        type(schema_version) is not int
                        or schema_version != _R2_DRIVER_SCHEMA_VERSION
                    ):
                        raise RuntimeError(
                            "r2dec container driver schema mismatch: "
                            f"expected {_R2_DRIVER_SCHEMA_VERSION}, got {schema_version}"
                        )
                    raw_entries = payload.get("functions")
                    if not isinstance(raw_entries, list) or not all(
                        isinstance(entry, dict) for entry in raw_entries
                    ):
                        raise RuntimeError("r2dec container returned malformed function records")
                    driver_command = payload.get("command")
                    if driver_command not in {"pdd", "pdc"}:
                        raise RuntimeError(
                            f"r2dec container returned invalid command: {driver_command}"
                        )
                    entries = raw_entries
                    used_cmd = driver_command
                else:
                    error = (
                        f"container produced no out.json (rc={proc.returncode}): "
                        f"{(proc.stderr or '')[-400:]}"
                    )
            except subprocess.TimeoutExpired:
                timed_out = True
                error = f"timeout after {self.container_timeout}s"
                _l.warning("%s docker timed out on %s", self.name, binary_path)
            except Exception as e:  # noqa: BLE001
                error = str(e)
                _l.error("%s docker failed on %s: %s", self.name, binary_path, e)

        by_addr: dict[int, tuple[str, dict[str, Any]]] = {}
        discovered: list[tuple[str, int, int]] = []
        for entry in entries:
            raw = entry.get("addr")
            if raw is None:
                continue
            b = int(entry.get("baddr") or 0)
            file_addr = int(raw) - b + elf_base
            nm = entry.get("name") or ""
            if _r2_is_import(nm) or nm in _R2_ENTRY_NAMES:
                continue
            if _skip_r2_function(_r2_bare_name(nm), file_addr, code_ranges, r2_addr_targets):
                continue
            by_addr[file_addr] = (nm, entry)
            discovered.append((nm, file_addr, int(raw)))
        discovered.sort(key=lambda t: t[1])
        targets = self._narrow(discovered, function_names, binary_path.name)

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        for label, file_addr, _raw, r2_flag in targets:
            _nm, entry = by_addr.get(file_addr, (r2_flag, {}))
            entry_baddr = _r2_int(entry.get("baddr"), 0) or 0
            fd = self._make_function(
                r2_flag,
                file_addr,
                str(entry.get("code") or ""),
                label,
                entry,
                r2_addr=_r2_int(entry.get("addr"), _raw),
                baddr=entry_baddr,
                elf_base=elf_base,
            )
            if fd is None:
                failed.append(label or _r2_bare_name(r2_flag))
            else:
                decompiled[fd.name] = fd
        if not entries and not decompiled:
            failed = failed or ["all"]

        result = self._make_result(
            binary_path,
            decompiled,
            failed,
            time.time() - start,
            "docker",
            used_cmd,
            output_dir,
            timed_out=timed_out,
            error=error,
        )
        raw_common.dump_progress(progress_path, result)
        self._write_artifacts(result, output_dir, binary_path)
        return result

    @staticmethod
    def _r2_baddr(r: Any) -> int:
        """radare2's load base address (``baddr``) for the open binary."""
        try:
            info = r.cmdj("ij") or {}
            return int((info.get("bin") or {}).get("baddr") or 0)
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _probe_decompile_cmd(r: Any) -> str:
        """Pick the decompile command: the real r2dec ``pdd`` or built-in ``pdc``."""
        try:
            out = r.cmd("pdd @ entry0")
        except Exception:  # noqa: BLE001
            out = ""
        if out and "install the plugin" not in out and "Cannot find" not in out:
            return "pdd"
        return "pdc"

    @staticmethod
    def _decompile_one_native(r: Any, cmd: str, addr: int) -> dict[str, Any] | None:
        """Decompile one function and collect r2-native provenance."""
        code = ""
        line_mappings: list[dict[str, Any]] = []
        if cmd in {"pdd", "pdc"}:
            payload = _r2_cmdj(r, f"{cmd}j @ {addr}", None)
            parsed = _r2_json_lines(payload) if cmd == "pdd" else _r2_json_annotations(payload)
            if parsed is not None:
                code, line_mappings = parsed
        if not code:
            raw = r.cmd(f"{cmd} @ {addr}")
            if raw:
                code = str(raw).strip()
        if not code or "install the plugin" in code:
            return None

        function_info = _r2_cmdj(r, f"afij @ {addr}", [])
        info = (
            function_info[0]
            if isinstance(function_info, list)
            and function_info
            and isinstance(function_info[0], dict)
            else {}
        )
        binary_info = _r2_cmdj(r, "ij", {})
        architecture = str((binary_info.get("bin") or {}).get("arch") or "").lower()
        is_thumb = architecture.startswith("arm") and (
            (_r2_int(info.get("bits"), 0) or 0) == 16 or bool(addr & 1)
        )
        return {
            "addr": addr,
            "size": _r2_int(info.get("size"), 0) or 0,
            "is_thumb": is_thumb,
            "code": code,
            "line_mappings": line_mappings,
            "variables": _r2_variable_records(r, addr, line_mappings),
        }


__all__ = [
    "DockerizedDecompiler",
    "RetDecDecompiler",
    "RekoDecompiler",
    "R2DecDecompiler",
    "elf_function_symbols",
    "split_c_functions",
]
