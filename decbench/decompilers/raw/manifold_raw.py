"""Manifold decompiler backend.

Manifold (https://github.com/changliu98/manifold) is a whole-binary decompiler that runs
CompCert's compilation pipeline in reverse: the binary is raised through Mach ->
Linear -> RTL -> Cminor -> Csharpminor -> Clight and printed as one C
translation unit. Unlike angr/Ghidra/IDA there is no per-function entry point --
one process call decompiles the whole binary and writes a single ``.c`` file.

This backend therefore:

* shells out to the ``manifold`` executable once per binary (with a timeout),
* splits the emitted translation unit into per-function definitions with a
  brace/string-aware scanner, and
* recovers each function's address from the ``FUN_<hex>`` names manifold gives
  functions in a stripped binary (falling back to the ELF symbol table when the
  binary still carries symbols).

Addresses are reported in **ELF-file space**, matching the other raw backends:
manifold reads the ELF's own virtual addresses, so its addresses are already in
that space and need no rebasing.

Variables are deliberately left unset: manifold's C output carries declared
types but no stack offsets, so ``type_match`` scores it through decbench's
``parse_c_variables`` text path (arguments by ABI position + locals by name),
exactly as it does for the code-only LLM backends.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.decompilers.spec import load_versions_config, version_settings
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

_l = logging.getLogger(__name__)

_FUN_NAME = re.compile(r"^FUN_([0-9a-fA-F]+)$")


def _executable(path: Path) -> Path | None:
    """``path`` if it is a runnable file, else None."""
    return path if path.is_file() and os.access(path, os.X_OK) else None


def _manifold_bin(version: str | None = None) -> Path | None:
    """Resolve the manifold executable.

    ``MANIFOLD_BIN`` is an explicit override and wins outright -- a bad value is
    a misconfiguration to report, not a reason to silently run some other build.
    Otherwise take ``binary`` from the decompilers config (per-version first,
    then the tool's default section), then fall back to ``$PATH``::

        [manifold]
        binary = "/opt/manifold/target/release/manifold"
        [manifold.versions."0.1"]
        binary = "/opt/manifold-0.1/target/release/manifold"
    """
    env = os.environ.get("MANIFOLD_BIN")
    if env:
        return _executable(Path(env))
    settings = [version_settings("manifold", version)]
    default = load_versions_config().get("manifold")
    if isinstance(default, dict):
        settings.append(default)
    for source in settings:
        binary = source.get("binary")
        if binary:
            exe = _executable(Path(str(binary)))
            if exe is not None:
                return exe
    which = shutil.which("manifold")
    return Path(which) if which else None


def _run_env() -> dict[str, str]:
    """Child environment: manifold links libz3 dynamically, so carry the extra
    library path (``MANIFOLD_LD_LIBRARY_PATH``) into ``LD_LIBRARY_PATH``."""
    env = dict(os.environ)
    extra = os.environ.get("MANIFOLD_LD_LIBRARY_PATH")
    if extra:
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{extra}:{prev}" if prev else extra
    # Manifold's rayon pool defaults to every core; a parallel driver must cap it.
    threads = os.environ.get("MANIFOLD_THREADS")
    if threads:
        env["RAYON_NUM_THREADS"] = threads
    return env


def _strip_comments_and_strings(text: str) -> str:
    """Blank out string/char literals and comments, preserving offsets.

    The function splitter scans for braces and parens; a ``'{'`` inside a string
    literal or a comment must not move the depth counter. Replacing those spans
    with spaces (same length) keeps every offset valid for slicing the original.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c in ("'", '"'):
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _declarator_name(decl: str) -> str | None:
    """The function name in a declarator like ``long FUN_401136(void *p0, int n)``.

    The parameter list is the paren group that closes at the end of ``decl``;
    the name is the identifier immediately before it.
    """
    decl = decl.strip()
    if not decl.endswith(")"):
        return None
    depth = 0
    open_i = None
    for i in range(len(decl) - 1, -1, -1):
        c = decl[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                open_i = i
                break
    if open_i is None:
        return None
    m = re.search(r"([A-Za-z_]\w*)\s*$", decl[:open_i])
    return m.group(1) if m else None


_IDENT = re.compile(r"[A-Za-z_]\w*")


class _Entity:
    """One top-level item of a manifold translation unit."""

    __slots__ = ("text", "defines", "refs", "is_function", "always")

    def __init__(self, text: str, defines: set[str], refs: set[str], is_function: bool):
        self.text = text
        self.defines = defines
        self.refs = refs
        self.is_function = is_function
        self.always = text.lstrip().startswith("#")


def parse_translation_unit(text: str) -> list[_Entity]:
    """Split a manifold translation unit into its top-level entities, in order.

    Walks top-level brace groups with a comment/string-aware scanner: the text
    since the last top-level ``;``/``}`` is the declarator, and a braced group
    whose declarator ends in a parameter list is a function definition (struct /
    union / enum definitions and prototypes end at a ``;`` instead).
    Preprocessor lines are their own entities.
    """
    scan = _strip_comments_and_strings(text)
    entities: list[_Entity] = []
    depth = 0
    decl_start = 0
    body_start = -1
    i, n = 0, len(scan)

    def emit(start: int, end: int, is_function: bool) -> None:
        chunk = text[start:end].strip()
        if not chunk:
            return
        idents = set(_IDENT.findall(_strip_comments_and_strings(chunk)))
        name = _declarator_name(text[start:body_start]) if is_function else None
        defines = {name} if name else _declared_names(chunk)
        entities.append(_Entity(chunk, defines, idents - defines, is_function))

    while i < n:
        c = scan[i]
        if depth == 0 and c == "#" and (i == 0 or scan[i - 1] == "\n"):
            j = scan.find("\n", i)
            j = n if j == -1 else j
            emit(decl_start, i, False)
            entities.append(_Entity(text[i:j].strip(), set(), set(), False))
            decl_start = j
            i = j
            continue
        if c == "{":
            if depth == 0:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                # A struct/union/enum definition continues to its ``;``.
                j = i + 1
                while j < n and scan[j] in " \t\r\n":
                    j += 1
                end = j + 1 if j < n and scan[j] == ";" else i + 1
                emit(decl_start, end, _declarator_name(text[decl_start:body_start]) is not None)
                decl_start = end
                body_start = -1
                i = end
                continue
        elif c == ";" and depth == 0:
            emit(decl_start, i + 1, False)
            decl_start = i + 1
        i += 1
    return entities


def _declared_names(chunk: str) -> set[str]:
    """Names a non-function top-level declaration introduces.

    Covers manifold's preamble forms: ``struct struct_1 { … };`` (the tag),
    ``long L_1f27b;`` / ``char L_2b031 = -1;`` / ``int L_205e0[1];`` (the
    variable), and ``extern unsigned char __TMC_END__;``.
    """
    body = _strip_comments_and_strings(chunk)
    m = re.match(r"\s*(?:typedef\s+)?(?:struct|union|enum)\s+([A-Za-z_]\w*)", body)
    if m:
        return {m.group(1)}
    head = re.split(r"[=;]", body, maxsplit=1)[0]
    head = re.sub(r"\[[^\]]*\]", "", head)
    m = re.search(r"([A-Za-z_]\w*)\s*$", head.strip())
    return {m.group(1)} if m else set()


def _with_preamble(func: _Entity, entities: list[_Entity]) -> str:
    """The function definition preceded by the file-scope items it references.

    Manifold prints one translation unit, but DecBench stores and recompiles one
    function at a time, so each function's stored code must carry the struct
    definitions and globals its body mentions -- transitively, since a struct's
    fields can name other structs. This mirrors the other backends' artifacts
    (angr's per-function code likewise repeats the typedefs and ``extern``
    globals the body uses).
    """
    by_name: dict[str, _Entity] = {}
    for e in entities:
        if e.is_function or e.always:
            continue
        for nm in e.defines:
            by_name.setdefault(nm, e)

    needed: set[int] = set()
    worklist = list(func.refs)
    seen: set[str] = set()
    while worklist:
        nm = worklist.pop()
        if nm in seen:
            continue
        seen.add(nm)
        ent = by_name.get(nm)
        if ent is None or id(ent) in needed:
            continue
        needed.add(id(ent))
        worklist.extend(ent.refs - seen)

    parts = [e.text for e in entities if e.always or id(e) in needed]
    parts.append(func.text)
    return "\n\n".join(parts)


def split_functions(text: str) -> list[tuple[str, str]]:
    """``(name, code)`` per function, each carrying the preamble it references."""
    entities = parse_translation_unit(text)
    out: list[tuple[str, str]] = []
    for e in entities:
        if not e.is_function:
            continue
        name = next(iter(e.defines), None)
        if name:
            out.append((name, _with_preamble(e, entities)))
    return out


def _symbol_addresses(binary_path: Path) -> dict[str, int]:
    """``name -> st_value`` for STT_FUNC symbols (unstripped binaries only)."""
    out: dict[str, int] = {}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    if not sym.name or not sym["st_value"]:
                        continue
                    out.setdefault(sym.name, int(sym["st_value"]))
    except Exception as e:  # noqa: BLE001
        _l.debug("manifold: no symbol table for %s: %s", binary_path, e)
    return out


@register_decompiler("manifold")
class ManifoldDecompiler(Decompiler):
    """Manifold driven as a one-shot whole-binary subprocess."""

    name = "manifold"
    display_name = "Manifold"

    def is_available(self) -> bool:
        return _manifold_bin(self.requested_version) is not None

    def get_version(self) -> str | None:
        env = os.environ.get("MANIFOLD_VERSION")
        if env:
            return env
        exe = _manifold_bin(self.requested_version)
        if exe is None:
            return None
        # No --version flag; identify the build by the revision it was built from.
        repo = exe.resolve().parents[2]
        try:
            rev = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if rev.returncode == 0 and rev.stdout.strip():
                return f"git-{rev.stdout.strip()}"
        except Exception:  # noqa: BLE001
            pass
        return self.requested_version or "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        result = self.decompile_binary(binary_path)
        return [(fd.name, fd.address) for fd in result.functions.values()]

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a whole binary in one manifold invocation.

        ``function_names`` carries the DWARF target *addresses* (the same
        contract as the other raw backends, see ``common.narrow_to_source``);
        manifold has no per-function entry point, so the narrowing is applied to
        the emitted functions rather than to the work.
        """
        exe = _manifold_bin(self.requested_version)
        if exe is None:
            raise RuntimeError("Decompiler 'manifold' is not available (set MANIFOLD_BIN)")

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)
        timeout_s = self.config.binary_timeout_seconds

        def _meta(failed: list[str], extra: dict[str, Any]) -> DecompilerMetadata:
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start_time,
                timeout_occurred=bool(extra.get("timeout")),
                failed_functions=failed,
                extra={"backend": "manifold", "via": "raw", **extra},
            )

        def _error(msg: str, timed_out: bool = False) -> DecompilationResult:
            _l.error("manifold failed on %s: %s", binary_path, msg)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=_meta(["all"], {"error": msg, "timeout": timed_out}),
                output_dir=output_dir,
            )

        with tempfile.TemporaryDirectory(prefix="manifold-dec-") as tmp:
            out_c = Path(tmp) / f"{binary_path.stem}.c"
            cmd = [str(exe), str(binary_path), str(out_c)]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    env=_run_env(),
                )
            except subprocess.TimeoutExpired:
                return _error(f"timeout after {timeout_s}s", timed_out=True)
            except Exception as e:  # noqa: BLE001
                return _error(f"spawn failed: {e}")

            if not out_c.is_file():
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
                return _error(f"no output (exit {proc.returncode}): {' | '.join(tail)}")
            text = out_c.read_text(errors="replace")

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        unaddressed: list[str] = []
        symbols: dict[str, int] | None = None

        for name, code in split_functions(text):
            m = _FUN_NAME.match(name)
            if m:
                file_addr = int(m.group(1), 16)
            else:
                # Symbol-named function: the binary was not stripped.
                if symbols is None:
                    symbols = _symbol_addresses(binary_path)
                addr = symbols.get(name)
                if addr is None:
                    unaddressed.append(name)
                    continue
                file_addr = addr
            if common.should_skip_function(name, file_addr, text_range):
                continue
            decompiled_functions[name] = FunctionDecompilation(
                name=name,
                address=file_addr,
                decompiled_code=code,
                line_count=len(code.splitlines()),
                metadata=common.extract_metrics(code),
            )

        kept = common.narrow_to_source(
            [(n, fd.address) for n, fd in decompiled_functions.items()],
            function_names,
            backend="manifold",
            binary_name=binary_path.name,
        )
        keep_names = {n for n, _ in kept}
        decompiled_functions = {n: fd for n, fd in decompiled_functions.items() if n in keep_names}

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=_meta(
                unaddressed,
                {"elf_base": elf_base, "translation_unit_lines": len(text.splitlines())},
            ),
            functions=decompiled_functions,
            combined_source=text,
            output_dir=output_dir,
        )

        common.dump_progress(progress_path, result)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result
