"""CFG extraction utilities."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.cfg import (
    CfgDiagnostic,
    CfgExtraction,
    CfgLanguage,
    CindergraphCfgExtractor,
    PreprocessingEvidence,
    extractor_info,
    graphs_from_extraction,
)
from decbench.cfg.cindergraph import CFG_SCHEMA_VERSION, EXTRACTION_POLICY_VERSION
from decbench.utils.langs import CXX_PREPROC_EXTS, PREPROC_EXTS

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult


_LINE_MARKER = re.compile(r'^#\s+\d+\s+"([^"]*)"')

# ``T [N] name(...)`` is not valid C and can drop a function from GED's denominator.
# Anchored at line start so it
# only rewrites a signature, never an in-body ``char buf[16];``.
_AGG_RETURN = re.compile(r"^([A-Za-z_][\w ]*?)\s*\[\d+\]\s+([A-Za-z_]\w*\s*\()", re.M)

# ``@`` register annotations are not legal C.
_REG_ANNOTATION = re.compile(r"\s*@\s*[a-z]\w+\b")
_PREPROCESSOR_CONTROL = re.compile(
    r"^\s*#\s*(?:define|undef|if|ifdef|ifndef|elif|else|endif)\b",
    re.M,
)
_FUNCTION_MARKER = re.compile(
    r"^// Function: ([A-Za-z_]\w*)(?: @ 0x[0-9a-fA-F]+)?\s*$",
    re.M,
)

# GNU computed goto (``goto *EXPR;``). Matched on masked text (see
# :func:`rewrite_computed_gotos`) so literals and comments are never rewritten;
# a plain ``goto label;`` has no ``*`` and never matches.
_COMPUTED_GOTO = re.compile(r"\bgoto\s*\*")

# Tab and newline are the emitted source's own layout, not literal payload.
_KEEP_RAW_BYTES = frozenset({0x09, 0x0A})


class UnsupportedCfgLanguage(ValueError):
    """The configured CFG extractor does not support this source language."""


def cfg_extractor_info() -> dict[str, object]:
    """Versioned identity persisted with CFGs and included in score provenance."""
    return extractor_info()


def escape_literal_control_bytes(text: str) -> str:
    """Escape raw control bytes appearing inside string/char literals.

    A decompiler that inlines ``.rodata`` verbatim emits e.g. an ANSI colour
    sequence as a raw ``0x1B``. Only literal interiors are rewritten, and
    ``\\x1b`` is the same
    bytes to the compiler, so control flow is untouched.
    """
    out: list[str] = []
    in_string = in_char = pending_escape = False
    for char in text:
        code = ord(char)
        if pending_escape:
            out.append(char)
            pending_escape = False
            continue
        if char == "\\" and (in_string or in_char):
            out.append(char)
            pending_escape = True
            continue
        if char == '"' and not in_char:
            in_string = not in_string
        elif char == "'" and not in_string:
            in_char = not in_char
        if (in_string or in_char) and code not in _KEEP_RAW_BYTES and (code < 0x20 or code == 0x7F):
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    return "".join(out)


def rewrite_computed_gotos(text: str) -> str:
    """Replace GNU computed gotos with an empty compound statement.

    ``goto *EXPR;`` is valid GNU C, but a topology-only graph cannot derive its
    dynamic target. The target of a computed goto is not
    statically derivable, so the statement contributes no CFG edge either way;
    replacing it with ``{}`` (rather than deleting it, which would break a
    braceless ``if (c) goto *p; else ...``) leaves exactly the control flow the
    surrounding code defines, with block roles intact. Matching runs on the
    comment/literal-masked text, so a ``"goto *"`` inside a string is never
    rewritten, and a plain ``goto label;`` never matches. Idempotent: the
    replacement contains no ``goto *``.
    """
    code = _mask_c_noncode(text)
    pieces: list[str] = []
    pos = 0
    for match in _COMPUTED_GOTO.finditer(code):
        if match.start() < pos:
            continue
        end = code.find(";", match.end())
        if end < 0:
            continue
        pieces.append(text[pos : match.start()])
        pieces.append("{}")
        pos = end + 1
    pieces.append(text[pos:])
    return "".join(pieces)


def sanitize_decompiled_c(text: str) -> str:
    """Clean decompiler-specific C quirks before CFG extraction.

    GED only cares about CFG *structure*, so these edits are purely to make the
    body parseable — they never touch control flow. Five quirks:

    * **Aggregate/array return type** (angr/ghidra): ``T [N] name(...)``
      is rewritten to ``T name(...)``. Anchored to the start of a line so a real
      in-body array declaration (``char buf[16];``) is never rewritten.
    * **Register annotation** (binja): `` @ rax`` (and friends) is stripped — ``@``
      is not valid C.
    * **128-bit types** (ida): ``__int128`` is widened to ``long long`` (the exact
      width is irrelevant to the CFG).
    * **Computed gotos** (any decompiler emitting GNU C): ``goto *EXPR;`` becomes
      an empty compound statement — see :func:`rewrite_computed_gotos`.
    * **Raw control bytes in literals**: escaped, so a verbatim ``.rodata`` string
      cannot confuse the C frontend's lexical boundaries.
    """
    text = _AGG_RETURN.sub(r"\1 \2", text)
    text = _REG_ANNOTATION.sub("", text)
    text = text.replace("unsigned __int128", "unsigned long long").replace("__int128", "long long")
    text = rewrite_computed_gotos(text)
    return escape_literal_control_bytes(text)


def needs_decompiled_preprocessing(text: str) -> bool:
    """Whether decompiled C contains directives whose expansion can change its CFG."""
    return _PREPROCESSOR_CONTROL.search(text) is not None


def _mask_c_noncode(text: str) -> str:
    masked = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                masked[index] = masked[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                masked[index] = masked[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {'"', "'"}:
                masked[index] = " "
                state = "string" if char == '"' else "character"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                masked[index] = masked[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                masked[index] = " "
        else:
            if char == "\\" and next_char:
                masked[index] = masked[index + 1] = " "
                index += 2
                continue
            masked[index] = " " if char != "\n" else "\n"
            if state == "string" and char == '"' or state == "character" and char == "'":
                state = "code"
        index += 1
    return "".join(masked)


def _definition_name_span(segment: str, name: str) -> tuple[int, int] | None:
    code = _mask_c_noncode(segment)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
        line_start = code.rfind("\n", 0, match.start()) + 1
        if code[line_start : match.start()].lstrip().startswith("#"):
            continue
        depth = 0
        for index in range(code.find("(", match.start()), len(code)):
            char = code[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    suffix = code[index + 1 :]
                    brace = suffix.find("{")
                    semicolon = suffix.find(";")
                    if brace >= 0 and (semicolon < 0 or brace < semicolon):
                        return match.start(), match.start() + len(name)
                    break
    return None


def _protect_macro_colliding_definitions(text: str) -> tuple[str, dict[str, str]]:
    markers = list(_FUNCTION_MARKER.finditer(text))
    replacements: list[tuple[int, int, str]] = []
    restore: dict[str, str] = {}
    for index, marker in enumerate(markers):
        name = marker.group(1)
        segment_start = marker.end()
        segment_end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        span = _definition_name_span(text[segment_start:segment_end], name)
        if span is None:
            continue
        sentinel = f"__decbench_function_{index}_macro_guard"
        if sentinel in text:
            raise ValueError(f"reserved preprocessing sentinel already present: {sentinel}")
        start, end = span
        replacements.append((segment_start + start, segment_start + end, sentinel))
        restore[sentinel] = name
    for start, end, sentinel in reversed(replacements):
        text = f"{text[:start]}{sentinel}{text[end:]}"
    return text, restore


def prepare_decompiled_c(
    text: str,
    *,
    timeout: float = 30.0,
) -> tuple[str, PreprocessingEvidence]:
    """Protect DecBench function markers, then use provider preprocessing."""
    if not needs_decompiled_preprocessing(text):
        return text, PreprocessingEvidence(status="not-needed")

    from cindergraph import source_cfg

    protected, restore = _protect_macro_colliding_definitions(text)
    report = source_cfg.preprocess_decompiled(protected, timeout=timeout)
    prepared = report.text
    for sentinel, name in restore.items():
        prepared = prepared.replace(sentinel, name)
    return prepared, PreprocessingEvidence(
        status=report.status,
        compiler=report.compiler,
        command=tuple(report.command),
        stderr=report.stderr,
        includes_removed=report.includes_removed,
    )


def preprocess_decompiled_c(text: str) -> str:
    """Expand locally defined macros before extracting decompiled-C CFGs."""
    return prepare_decompiled_c(text)[0]


def _is_system_header(path: str) -> bool:
    """True if a preprocessor line-marker file is a system/toolchain header.

    Covers glibc (/usr/include), gcc internals (/usr/lib/gcc), the cross/mingw
    toolchains (also under /usr/...), and the preprocessor's synthetic files
    (<built-in>, <command-line>, stdc-predef.h).
    """
    return (
        not path
        or path.startswith("<")
        or path.startswith("/usr/")
        or "/usr/lib/gcc" in path
        or path.endswith("stdc-predef.h")
    )


def strip_system_headers(preprocessed: str) -> str:
    """Drop inlined system-header code from a preprocessed (``.i``/``.ii``) unit.

    A preprocessed file is the project source with every ``#include`` expanded inline,
    so it is dominated by glibc/toolchain headers. Keeping only project text avoids
    extracting thousands of irrelevant inline functions.

    Using the ``# <line> "<file>"`` markers gcc emits, we keep only lines that
    came from the project's own files. ``#ifdef`` selection and macro expansion
    have ALREADY been done by the real compiler, so the result is exactly the
    code that was compiled (the right ifdef branches) — fair and small.
    """
    keep: list[str] = []
    in_system = True
    for line in preprocessed.splitlines():
        m = _LINE_MARKER.match(line)
        if m is not None:
            in_system = _is_system_header(m.group(1))
            continue
        if not in_system:
            keep.append(line)
    return "\n".join(keep) + "\n"


def is_degenerate_source_cfg(cfg: DiGraph) -> bool:  # type: ignore
    """True when a source CFG has no real structure to compare GED against.

    Two cases, both meaning "there is nothing to score": zero nodes, or a single
    block whose statements are ALL ``Nop`` (``FUNCTION_START``/``FUNCTION_END``) —
    an empty declaration-only view of a function
    whose defining translation unit wasn't captured. A genuine single-block
    function (a straight-line ``return foo(...);``) has real statements and is NOT
    degenerate, so it stays scorable (a correct 1-block decompilation → GED 0).
    """
    explicit = cfg.graph.get("degenerate")
    if explicit is not None:
        return bool(explicit)
    n = cfg.number_of_nodes()
    if n == 0:
        return True
    if n >= 2:
        return False
    for node in cfg.nodes():
        for stmt in getattr(node, "statements", None) or []:
            if type(stmt).__name__ != "Nop":
                return False
    return True


def _source_rank(cfg: DiGraph) -> tuple[int, int]:  # type: ignore
    """Sort key preferring a non-degenerate, then larger, source CFG."""
    return (0 if is_degenerate_source_cfg(cfg) else 1, cfg.number_of_nodes())


def best_source_by_name(
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]],
) -> dict[str, DiGraph]:  # type: ignore
    """Collapse per-TU source CFGs to one-per-name, preferring the real body.

    A function name that appears in several translation units (``main``, ``usage``,
    gnulib helpers) is reduced to its **non-degenerate, largest** CFG. Used as the
    cross-TU FALLBACK when a binary's own TU doesn't define a function (e.g. a
    statically-linked gnulib helper) — see :func:`resolved_source_for_binary`.
    """
    best: dict[str, DiGraph] = {}
    for cfgs in source_cfgs_by_binary.values():
        for name, cfg in (cfgs or {}).items():
            cur = best.get(name)
            if cur is None or _source_rank(cfg) > _source_rank(cur):
                best[name] = cfg
    return best


def resolved_source_for_binary(
    binary_stem: str,
    source_cfgs_by_binary: dict[str, dict[str, DiGraph]],
    best_by_name: dict[str, DiGraph],
    function_owners: Mapping[int, tuple[str, str]] | None = None,
) -> dict[str, DiGraph]:  # type: ignore
    """Source CFGs to score ONE binary against, TU-aware (fixes name collisions).

    Prefers the binary's **own translation unit** (``nologin`` binary ↔
    ``nologin.i``) for each function so per-program functions (``main``, ``usage``,
    static helpers) are compared against the RIGHT body — not an arbitrary
    same-named function from another binary of the project (the old project-wide,
    name-keyed, last-writer-wins union scored ``nologin``'s 5-node ``main`` against
    another binary's 56-node ``main``). Falls back to the cross-TU
    :func:`best_source_by_name` for functions the own TU doesn't define
    (statically-linked library code) or defines only as an empty prototype.

    ``function_owners`` carries exact DWARF ``low_pc -> (name, decl-file TU)``
    provenance. It takes priority over the binary-stem convention, which is not
    reliable when a build names an output differently from its defining source.
    A known owner with no real CFG abstains for that name instead of selecting a
    same-named function from another translation unit.
    """
    resolved = dict(best_by_name)
    for name, cfg in (source_cfgs_by_binary.get(binary_stem) or {}).items():
        if not is_degenerate_source_cfg(cfg):
            resolved[name] = cfg

    owned_by_name: dict[str, str] = {}
    ambiguous: set[str] = set()
    for name, tu_stem in (function_owners or {}).values():
        previous = owned_by_name.get(name)
        if previous is not None and previous != tu_stem:
            ambiguous.add(name)
        else:
            owned_by_name[name] = tu_stem
    for name in ambiguous:
        owned_by_name.pop(name, None)

    for name, tu_stem in owned_by_name.items():
        cfg = (source_cfgs_by_binary.get(tu_stem) or {}).get(name)
        if cfg is None or is_degenerate_source_cfg(cfg):
            resolved.pop(name, None)
        else:
            resolved[name] = cfg
    return resolved


def extract_cfg_records_from_decompilation(
    decompilation: DecompilationResult,
) -> CfgExtraction:
    """Return typed CFG records and recovery evidence for generated C."""
    marked_sources = [
        f"// Function: {func.name}\n{func.decompiled_code}"
        for func in decompilation.functions.values()
    ]
    text = sanitize_decompiled_c("\n\n".join(marked_sources))
    prepared, preprocessing = prepare_decompiled_c(text)
    extractor = CindergraphCfgExtractor()
    try:
        extraction = extractor.extract_decompiled(prepared)
    except Exception as error:  # noqa: BLE001 - provider failures are typed evidence
        return CfgExtraction(
            functions={},
            provider=extractor.name,
            provider_version=extractor.version,
            cfg_schema=CFG_SCHEMA_VERSION,
            extraction_policy=EXTRACTION_POLICY_VERSION,
            language="c",
            status="failed",
            diagnostics=(CfgDiagnostic(code="provider-failure", message=str(error)),),
            preprocessing=preprocessing,
        )
    return replace(
        extraction,
        preprocessing=preprocessing,
    )


def extract_cfg_records_from_source(source_path: Path) -> CfgExtraction:
    """Return the typed provider result for one source translation unit.

    This is the non-lossy pipeline boundary. The older graph-returning wrapper
    below remains for callers that predate typed extraction outcomes.
    """
    language: CfgLanguage = "c++" if source_path.suffix in CXX_PREPROC_EXTS else "c"
    text = source_path.read_text(errors="replace")
    if source_path.suffix in PREPROC_EXTS:
        text = strip_system_headers(text)
    extractor = CindergraphCfgExtractor()
    try:
        return extractor.extract_source(source_path, text, language)
    except Exception as error:  # noqa: BLE001 - provider failures are typed evidence
        return CfgExtraction(
            functions={},
            provider=extractor.name,
            provider_version=extractor.version,
            cfg_schema=CFG_SCHEMA_VERSION,
            extraction_policy=EXTRACTION_POLICY_VERSION,
            language=language,
            status="failed",
            diagnostics=(CfgDiagnostic(code="provider-failure", message=str(error)),),
        )


def extract_cfgs_from_source(
    source_path: Path,
    sanitize_decompiled: bool = False,
    preprocess_decompiled: bool = True,
    raise_on_error: bool = False,
) -> dict[str, DiGraph]:
    """Extract CFGs from a C source file using Cindergraph.

    Args:
        source_path: Path to a source file (``.c`` or preprocessed ``.i``).
            For preprocessed files the inlined system headers are stripped first
            (see :func:`strip_system_headers`) so extraction sees only the project's
            own (already-preprocessed, correctly-ifdef'd) code.
        sanitize_decompiled: When True and ``source_path`` is a *decompiled* ``.c``
            (i.e. NOT a preprocessed ground-truth source), run its text through
            :func:`sanitize_decompiled_c` before parsing so decompiler-specific
            quirks don't drop the function from GED. Never applied to preprocessed
            files — sanitizing ground truth would be wrong.
        preprocess_decompiled: Expand local preprocessing directives after
            sanitization. Disable only to reproduce historical decompiled-side
            CFG inputs for an audit.
        raise_on_error: Propagate parser failures instead of treating them as an
            empty parse. Unsupported C++ always raises rather than silently
            appearing to be an empty C translation unit.

    Returns:
        Dictionary mapping function names to CFG DiGraphs
    """
    if not sanitize_decompiled:
        extraction = extract_cfg_records_from_source(source_path)
        if not extraction.supported:
            raise UnsupportedCfgLanguage(
                f"Cindergraph CFG extraction supports C, not C++: {source_path}"
            )
        if extraction.status == "failed":
            message = "; ".join(diagnostic.message for diagnostic in extraction.diagnostics)
            logger.warning(
                "Cindergraph CFG extraction from source %s failed: %s", source_path, message
            )
            if raise_on_error:
                raise RuntimeError(message)
            return {}
        return graphs_from_extraction(extraction)

    if source_path.suffix in CXX_PREPROC_EXTS:
        raise UnsupportedCfgLanguage(
            f"Cindergraph CFG extraction supports C, not C++: {source_path}"
        )
    text = source_path.read_text(errors="replace")
    text = sanitize_decompiled_c(text)
    extractor = CindergraphCfgExtractor()

    try:
        if preprocess_decompiled:
            prepared, preprocessing = prepare_decompiled_c(text)
            extraction = replace(
                extractor.extract_decompiled(prepared),
                preprocessing=preprocessing,
            )
        else:
            extraction = extractor.extract_source(source_path, text, "c")
        return graphs_from_extraction(extraction)
    except Exception as error:
        logger.warning("Cindergraph CFG extraction from source %s failed: %s", source_path, error)
        if raise_on_error:
            raise
        return {}


def extract_cfgs_from_decompilation(
    decompilation: DecompilationResult,
) -> dict[str, DiGraph]:
    """Extract CFGs from decompiled code.

    Args:
        decompilation: Decompilation result

    Returns:
        Dictionary mapping function names to CFG DiGraphs
    """
    extraction = extract_cfg_records_from_decompilation(decompilation)
    if extraction.status == "failed":
        details = "; ".join(item.message for item in extraction.diagnostics)
        logger.warning("Cindergraph CFG extraction from decompilation failed: %s", details)
        return {}
    return graphs_from_extraction(extraction)
