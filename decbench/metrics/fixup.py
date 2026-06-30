"""Compilability fixup for decompiled C (the byte-match preprocessing pass).

Decompiler output rarely compiles as-is: Ghidra emits pseudo-types it never
defines (``undefined4``, ``code``, ``uint``), angr emits illegal C tokens like
``GLIBC_2.2.5::stderr`` (symbol-version names) and calls helpers that have no
declaration. The recompilation byte-match metric scores any non-compiling
function as 0, so this pass exists to give every decompiler a fair shot at
recompiling: we *maximize compilation* by repairing the code the same way for
everyone, then let the (operand-normalized) assembly diff judge correctness.

Strategy — deliberately conflict-safe:

1. **Token sanitization** removes constructs no C compiler accepts (``NS::id``
   version names) but that are unambiguous in decompiler output.
2. **Minimal includes** (``stdint``/``stddef`` only) — NOT the full stdlib —
   so the scaffolding never collides with a decompiler's own ``typedef struct
   FILE {}`` etc. (forcing ``stdio.h`` was a real cause of redefinition errors).
3. **gcc-error-driven self-repair**: compile, read the diagnostics, and inject
   *only* the declarations gcc says are missing (``unknown type name`` →
   ``typedef``; ``implicit declaration`` → function decl; ``undeclared`` →
   global). Because we add only what the compiler asks for, we never redefine
   something the decompiler already declared. Conflicts that we *do* cause
   (rare) are detected and the offending injected decl is withdrawn.

The cost is some ABI/codegen noise (a synthesized ``long foo();`` may not match
the real signature), but the metric's operand normalization absorbs the largest
source of that noise (call/branch targets), and the alternative — scoring 84% of
Ghidra functions as a flat 0 because they reference ``undefined4`` — is far less
fair. Applied uniformly to all decompilers, this isolates *logic* recompilation
from *type recovery* (which ``type_match`` measures separately).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# gcc localizes diagnostics and (by default) quotes identifiers with Unicode
# curly quotes (' ') — force the C locale so it emits plain ASCII quotes that the
# repair regexes below can match. (The regexes also accept curly quotes as a
# fallback, in case a toolchain ignores the locale.)
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}
_Q = r"['‘’“”]"  # ascii ' or " plus curly variants

# Strip a leading ``Namespace::`` qualifier (e.g. ``GLIBC_2.2.5::stderr`` ->
# ``stderr``). Decompiled C never uses real C++ scope resolution, so any ``::``
# is a symbol-version artifact we can safely drop.
_NS_QUALIFIER = re.compile(r"\b[A-Za-z_][\w.$]*::")

# Decompiler-specific function/type ANNOTATIONS that aren't valid C in the place
# they appear (Binary Ninja's ``__noreturn``/``__convention("...")``/``__pure``
# suffixes, IDA/Ghidra ``__cdecl``/``__fastcall``/``__thiscall`` calling-conv
# keywords, ``__packed``). Dropping them lets the body still compile; they don't
# affect the recovered logic the byte-match is measuring.
_ANNOTATIONS = re.compile(
    r"\b__(?:noreturn|pure|const|packed|noreturn__|hidden|usercall|userpurge"
    r"|cdecl|stdcall|fastcall|thiscall|vectorcall)\b"
    r"|\b__convention\s*\([^)]*\)"
    r'|\b__(?:reg|stack)\s*\("[^"]*"\)'
)

# Minimal, conflict-safe scaffolding. Only fixed-width int + size types; nothing
# that defines FILE/struct names a decompiler might also define.
_MINIMAL_INCLUDES = "#include <stdint.h>\n#include <stddef.h>\n"

# Sensible C type for a Ghidra/IDA/angr pseudo-type, chosen so the *width* (and
# thus most codegen) matches. Anything unknown falls back to ``long``.
_TYPE_GUESS: dict[str, str] = {
    "undefined": "unsigned char",
    "undefined1": "unsigned char",
    "undefined2": "unsigned short",
    "undefined3": "unsigned int",
    "undefined4": "unsigned int",
    "undefined5": "unsigned long",
    "undefined6": "unsigned long",
    "undefined7": "unsigned long",
    "undefined8": "unsigned long",
    "byte": "unsigned char",
    "uchar": "unsigned char",
    "sbyte": "signed char",
    "ushort": "unsigned short",
    "word": "unsigned short",
    "uint": "unsigned int",
    "dword": "unsigned int",
    "uint3": "unsigned int",
    "ulong": "unsigned long",
    "qword": "unsigned long",
    "uint5": "unsigned long",
    "uint6": "unsigned long",
    "uint7": "unsigned long",
    "ulonglong": "unsigned long long",
    "longlong": "long long",
    "code": "void",
    "pointer": "void *",
    "__int8": "char",
    "__int16": "short",
    "__int32": "int",
    "__int64": "long long",
    "__uint8": "unsigned char",
    "__uint16": "unsigned short",
    "__uint32": "unsigned int",
    "__uint64": "unsigned long long",
    "float10": "long double",
    "unkbyte10": "long double",
    "unkuint10": "long double",
}

_MAX_REPAIR_ITERS = 8


def sanitize_tokens(code: str) -> str:
    """Remove constructs no C compiler accepts but that are unambiguous.

    Currently: strip ``Namespace::`` symbol-version qualifiers (keeping the bare
    identifier, ``GLIBC_2.2.5::stderr`` -> ``stderr``) and decompiler annotation
    keywords (``__noreturn``, ``__convention(...)``, ``__cdecl``, ...).
    """
    code = _NS_QUALIFIER.sub("", code)
    code = _ANNOTATIONS.sub("", code)
    return code


def _type_guess(name: str) -> str:
    """Best-effort concrete C type for an undefined pseudo-type name."""
    if name in _TYPE_GUESS:
        return _TYPE_GUESS[name]
    low = name.lower()
    if low in _TYPE_GUESS:
        return _TYPE_GUESS[low]
    # undefinedN / uintN / intN width hints.
    m = re.fullmatch(r"u?int(\d+)", low)
    if m:
        bits = int(m.group(1))
        width = "unsigned " if low.startswith("u") else ""
        if bits <= 8:
            return f"{width}char"
        if bits <= 16:
            return f"{width}short"
        if bits <= 32:
            return f"{width}int"
        return f"{width}long"
    return "long"


@dataclass
class FixupResult:
    """Outcome of a fixup compile attempt."""

    obj_path: Path | None
    source: str
    compilable: bool
    iterations: int
    injected: list[str] = field(default_factory=list)
    error: str | None = None


# Diagnostic patterns gcc emits that we know how to repair.
_RE_UNKNOWN_TYPE = re.compile(rf"unknown type name {_Q}([A-Za-z_]\w*){_Q}")
_RE_IMPLICIT_FUNC = re.compile(rf"implicit declaration of function {_Q}([A-Za-z_]\w*){_Q}")
_RE_UNDECLARED = re.compile(rf"{_Q}([A-Za-z_]\w*){_Q} undeclared")
_RE_NOT_A_FUNC = re.compile(rf"called object {_Q}([A-Za-z_]\w*){_Q}[^\n]*is not a function")
# A conflict caused by one of OUR injected declarations.
_RE_CONFLICT = re.compile(
    r"(?:conflicting types for|redefinition of|redeclared as|previous declaration of) "
    rf"{_Q}([A-Za-z_]\w*){_Q}"
)


def _build_source(code: str, decls: dict[str, str]) -> str:
    """Assemble the candidate translation unit: includes + injected decls + code."""
    inject = "\n".join(decls[k] for k in sorted(decls))
    return _MINIMAL_INCLUDES + inject + ("\n\n" if inject else "\n") + code


def _gcc_compile(
    src: str, obj_path: Path, compiler: str, flags: list[str]
) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(src)
        src_path = Path(f.name)
    try:
        return subprocess.run(
            [compiler, *flags, "-o", str(obj_path), str(src_path)],
            capture_output=True,
            timeout=30,
            text=True,
            env=_C_LOCALE_ENV,
        )
    finally:
        src_path.unlink(missing_ok=True)


def compile_with_fixup(
    code: str,
    func_name: str,
    compiler: str = "gcc",
    flags: list[str] | None = None,
) -> FixupResult:
    """Compile decompiled ``code`` to an object file, maximizing the odds it builds.

    Runs token sanitization, then a gcc-diagnostic-driven self-repair loop that
    injects only the declarations the compiler reports missing. Returns a
    :class:`FixupResult`; ``obj_path`` is set (and exists) iff compilation
    eventually succeeded. The caller owns ``obj_path`` and must unlink it.
    """
    if flags is None:
        flags = ["-O2", "-c", "-fno-builtin", "-w"]

    code = sanitize_tokens(code)
    decls: dict[str, str] = {}
    # Track which names we injected (so we can withdraw on a conflict we caused).
    obj_dir = Path(tempfile.mkdtemp(prefix="decbench_bm_"))
    obj_path = obj_dir / f"{func_name}.o"

    def fail(src: str, iteration: int, error: str) -> FixupResult:
        # Only the SUCCESS path hands the temp dir to the caller; every failure
        # must clean it up here or we leak an empty dir per non-compiling func.
        shutil.rmtree(obj_dir, ignore_errors=True)
        return FixupResult(None, src, False, iteration, [d for d in decls.values() if d], error)

    last_err = ""
    for iteration in range(1, _MAX_REPAIR_ITERS + 1):
        src = _build_source(code, decls)
        try:
            proc = _gcc_compile(src, obj_path, compiler, flags)
        except subprocess.TimeoutExpired:
            return fail(src, iteration, "timeout")
        except FileNotFoundError:
            return fail(src, iteration, "compiler-not-found")

        if proc.returncode == 0 and obj_path.exists():
            return FixupResult(obj_path, src, True, iteration, [d for d in decls.values() if d])

        last_err = proc.stderr
        added = False

        # 1) Withdraw any injected decl that caused a conflict, and avoid re-adding.
        #    Guard on truthiness so an already-blanked (or non-injected) name does
        #    NOT keep re-firing `added` — otherwise a persistent conflict between
        #    two decompiler-provided decls burns all _MAX_REPAIR_ITERS gcc runs.
        for name in _RE_CONFLICT.findall(last_err):
            if decls.get(name):
                # Our decl clashed with a decompiler-provided one; drop ours.
                decls[name] = ""  # blank keeps it "claimed" so we don't re-add
                added = True

        # 2) unknown type name -> typedef a width-matched concrete type.
        for name in _RE_UNKNOWN_TYPE.findall(last_err):
            if name not in decls:
                decls[name] = f"typedef {_type_guess(name)} {name};"
                added = True

        # 3) implicit function declaration / called-non-function -> declare a func.
        for name in set(_RE_IMPLICIT_FUNC.findall(last_err)) | set(
            _RE_NOT_A_FUNC.findall(last_err)
        ):
            decl = f"long {name}();"
            if decls.get(name) != decl:
                decls[name] = decl
                added = True

        # 4) undeclared identifier -> a global (unless we already made it a func).
        for name in _RE_UNDECLARED.findall(last_err):
            if name not in decls:
                decls[name] = f"long {name};"
                added = True

        if not added:
            break  # nothing actionable left; give up

    return fail(
        _build_source(code, decls),
        iteration,
        (last_err or "").strip()[-400:] or "unrepairable",
    )
