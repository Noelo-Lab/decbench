"""Best-effort extraction of a single function's *source* text.

Powers the report's "Compare samples" view (original source next to each
decompiler's output) and fills in :attr:`HardestEntry.source_code`. There is no
perfect way to slice a C function out of a translation unit without a full
parser, so this is heuristic but conservative:

1. Read the function's ``decl_file`` / ``decl_line`` from the binary's DWARF
   (when present) to know *which* source file and roughly *where*.
2. Find the matching original ``.c`` next to the binary (the compile stage keeps
   per-binary sources in ``compiled/``), then locate the function *definition*
   (not a call/prototype) and brace-match its body.

Returns ``None`` whenever anything is uncertain rather than guessing wrong.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def _dwarf_decl(binary_path: Path) -> dict[str, tuple[str, int]]:
    """Map function name -> (decl_file basename, decl_line) from DWARF.

    Empty dict when DWARF is missing/unreadable (callers then search all
    sibling sources without a line hint).
    """
    out: dict[str, tuple[str, int]] = {}
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:  # noqa: BLE001
        return out
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return out
            dw = elf.get_dwarf_info()
            for cu in dw.iter_CUs():
                lp = dw.line_program_for_CU(cu)
                # DW_AT_decl_file indexing differs by DWARF version: pre-v5 is
                # 1-based (entry 0 is unused), v5 is 0-based (entry 0 is the
                # primary source). Prepend a placeholder only for pre-v5 so the
                # index lines up either way.
                version = 4
                if lp is not None:
                    version = lp.header.get("version", cu.header.get("version", 4))
                files: list = [] if version >= 5 else [None]
                if lp is not None:
                    for fe in lp["file_entry"]:
                        nm = fe.name
                        files.append(nm.decode() if isinstance(nm, bytes) else nm)
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    attrs = die.attributes
                    if "DW_AT_name" not in attrs or "DW_AT_low_pc" not in attrs:
                        continue
                    nm = attrs["DW_AT_name"].value
                    name = nm.decode() if isinstance(nm, bytes) else nm
                    fi = attrs.get("DW_AT_decl_file")
                    ln = attrs.get("DW_AT_decl_line")
                    fname = None
                    if fi is not None and 0 <= fi.value < len(files):
                        fname = files[fi.value]
                    line = int(ln.value) if ln is not None else 0
                    out[name] = (os.path.basename(fname) if fname else "", line)
    except Exception:  # noqa: BLE001
        return out
    return out


def _match_braces(text: str, open_idx: int) -> int | None:
    """Index just past the ``}`` matching the ``{`` at ``open_idx`` (string/char
    and comment aware). ``None`` if unbalanced."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _match_paren(text: str, open_idx: int) -> int | None:
    """Index of the ``)`` matching the ``(`` at ``open_idx`` (depth-counted).

    Needed because a function's parameter list can itself contain parentheses
    (function-pointer params, casts, ``__attribute__((...))``), so the *first*
    ``)`` is not the end of the signature. ``None`` if unbalanced.
    """
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def extract_from_text(text: str, func_name: str, decl_line: int = 0) -> str | None:
    """Extract ``func_name``'s definition from C ``text`` via brace matching.

    When ``decl_line`` (1-based) is given, prefer the candidate nearest it.
    Returns the signature + body, or ``None`` if no definition is found.
    """
    pat = re.compile(r"(^|[^\w])" + re.escape(func_name) + r"\s*\(")
    lines = text.splitlines(keepends=True)
    # Precompute byte offset of each line start for decl_line proximity.
    offsets = []
    acc = 0
    for ln in lines:
        offsets.append(acc)
        acc += len(ln)

    # (proximity, signature_start_offset, body_end_offset)
    candidates: list[tuple[int, int, int]] = []
    for m in pat.finditer(text):
        paren = text.index("(", m.start())
        close = _match_paren(text, paren)
        if close is None:
            continue
        # The next non-space char after ')' must be '{' for a definition.
        j = close + 1
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != "{":
            continue  # prototype, call, or K&R — skip the simple case
        # Reject if this looks like a call inside another body: require the
        # token before the name (ignoring the return type) to start a logical
        # line — i.e. the line's first non-space isn't itself a statement.
        line_no = text.count("\n", 0, m.start())  # 0-based
        # Find start of the signature: walk back to the line that begins the
        # return type (previous blank line or '}' / ';').
        sig_start = text.rfind("\n", 0, m.start())
        # extend upward over the return-type line(s)
        k = line_no
        while k > 0:
            prev = lines[k - 1].strip()
            if prev == "" or prev.endswith(("}", ";", "*/", "{")) or prev.startswith(("#", "//")):
                break
            k -= 1
        sig_start = offsets[k]
        end = _match_braces(text, j)
        if end is None:
            continue
        prox = abs((line_no + 1) - decl_line) if decl_line else 0
        candidates.append((prox, sig_start, end))

    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0], c[1]))
    _, start, end = candidates[0]
    snippet = text[start:end].strip("\n")
    return snippet or None


def function_source(binary_path: Path, func_name: str) -> str | None:
    """Best-effort source text for ``func_name`` defined in ``binary_path``.

    Looks for the original ``.c`` sources kept next to the binary (the compile
    stage writes them into ``compiled/``), guided by DWARF when available.
    """
    decl = _dwarf_decl(binary_path)
    decl_file, decl_line = decl.get(func_name, ("", 0))

    search_dir = binary_path.parent
    sources = sorted(p for p in search_dir.glob("*.c") if p.is_file())
    if not sources:
        return None

    # Prefer the DWARF-named file, then any file containing the name.
    ordered: list[Path] = []
    if decl_file:
        for p in sources:
            if p.name == decl_file or p.stem == os.path.splitext(decl_file)[0]:
                ordered.append(p)
    ordered += [p for p in sources if p not in ordered]

    for p in ordered:
        try:
            text = p.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if func_name not in text:
            continue
        line_hint = decl_line if (decl_file and p.name == decl_file) else 0
        snippet = extract_from_text(text, func_name, line_hint)
        if snippet:
            return snippet
    return None
