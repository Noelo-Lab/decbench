"""Compile one decompiled function for the byte-match metric.

byte_match recompiles every decompiled function on its own and diffs the
assembly against the original. This module owns the part of that step that is
identical for every decompiler: the compiler invocation, a neutral flag policy,
a bounded attempt loop, and a private summary of terminal diagnostics.

Everything decompiler-specific lives in that decompiler's fixup module,
``decbench/metrics/fixups/generated/<name>.py``. Each one is written by the same
time-boxed fixup agent from the same prompt (``decbench/metrics/fixups/
PROMPT.md``, driven by ``scripts/fixup_agent.py``); see
:mod:`decbench.metrics.fixups` for the contract. A decompiler without a module
is compiled exactly as it was emitted.

Neutral flag policy, applied before the module's ``FLAGS``: ``-w`` is dropped
so warnings reach a module's ``repair`` hook, ``-std=gnu17`` is added when the
caller selected no language mode, and GCC 14's new pointer/integer conversion
errors are demoted back to warnings.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from decbench.metrics.fixups import FixupContext, FixupError, module_flags

_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}

MAX_ATTEMPTS = 8
COMPILE_TIMEOUT = 30

_DIAGNOSTIC_LINE = re.compile(r"^(?:.*?:\s*)?((?:fatal )?error):\s*(.+)$", re.MULTILINE)
_DIAGNOSTIC_CLASS = re.compile(r"\[(-W[^\]\s]+)\]")
_DIAGNOSTIC_QUOTED = re.compile(r"'[^'\n]*'|‘[^’\n]*’|“[^”\n]*”|\"[^\"\n]*\"")
_DIAGNOSTIC_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:)?[/\\][^\s:]+")
_DIAGNOSTIC_SOURCE_EXCERPT = re.compile(r"^\s*\d+\s*\|")
_DIAGNOSTIC_LIMIT = 400


@dataclass
class FixupResult:
    """Outcome of compiling one function.

    ``obj_path`` is set (and exists) iff compilation succeeded; the caller owns
    it and must remove its parent directory. ``stderr`` is the last compiler
    output, kept for the fixup workbench and never persisted by the metric.
    """

    obj_path: Path | None
    source: str
    compilable: bool
    iterations: int
    error: str | None = None
    stderr: str = ""


def _summarize_compiler_errors(stderr: str) -> str:
    """Return a bounded, deterministic summary of compiler error lines."""
    classes: set[str] = set()
    messages: set[str] = set()
    for line in stderr.splitlines():
        if _DIAGNOSTIC_SOURCE_EXCERPT.match(line):
            continue
        match = _DIAGNOSTIC_LINE.match(line)
        if match is None:
            continue
        severity, message = match.groups()
        classes.update(_DIAGNOSTIC_CLASS.findall(message))
        message = _DIAGNOSTIC_CLASS.sub("", message)
        message = _DIAGNOSTIC_QUOTED.sub("<redacted>", message)
        message = _DIAGNOSTIC_ABSOLUTE_PATH.sub("<path>", message)
        if message.endswith(": No such file or directory"):
            message = re.sub(r"^\S+(?=: No such file or directory$)", "<path>", message)
        message = " ".join(message.split()).strip()
        if message:
            messages.add(f"{severity}: {message}")

    if not messages:
        return "unrepairable"

    class_prefix = f" [{', '.join(sorted(classes))}]" if classes else ""
    summary = f"compiler diagnostics{class_prefix}: {'; '.join(sorted(messages))}"
    if len(summary) <= _DIAGNOSTIC_LIMIT:
        return summary

    clipped = summary[: _DIAGNOSTIC_LIMIT - 3]
    boundary = max(clipped.rfind(" "), clipped.rfind(";"))
    if boundary >= _DIAGNOSTIC_LIMIT // 2:
        clipped = clipped[:boundary]
    return clipped.rstrip(" ,;") + "..."


def _has_language_mode(flags: list[str]) -> bool:
    """Whether direct caller flags select a C language mode."""
    for index, flag in enumerate(flags):
        if flag in {"-ansi", "--ansi"} or flag.startswith(("-std=", "--std=")):
            return True
        if (
            flag in {"-std", "--std"}
            and index + 1 < len(flags)
            and not flags[index + 1].startswith("-")
        ):
            return True
    return False


def neutral_flags(flags: list[str] | None) -> list[str]:
    """The caller's flags under the decompiler-neutral policy (caller list untouched)."""
    out = [f for f in (flags if flags is not None else ["-O2", "-c", "-fno-builtin"]) if f != "-w"]
    if not _has_language_mode(out):
        out.append("-std=gnu17")
    out.extend(["-Wno-error=incompatible-pointer-types", "-Wno-error=int-conversion"])
    return out


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
            timeout=COMPILE_TIMEOUT,
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
    fixup: ModuleType | None = None,
    siblings: dict[str, str] | None = None,
    binary_key: str = "",
) -> FixupResult:
    """Compile ``code`` to an object file through ``fixup`` (a fixup module, or None).

    The module's ``prepare`` builds the translation unit and its optional
    ``repair`` may revise it from the compiler's stderr, for at most
    :data:`MAX_ATTEMPTS` compiles. A module that raises, or returns something
    other than a string, fails the function rather than falling back to the
    raw code.
    """
    base = neutral_flags(flags)
    ctx = FixupContext(
        func_name=func_name,
        siblings=siblings or {},
        binary_key=binary_key,
        compiler=compiler,
        flags=tuple(base),
    )
    obj_dir = Path(tempfile.mkdtemp(prefix="decbench_bm_"))
    obj_path = obj_dir / f"{func_name}.o"

    def fail(src: str, attempts: int, error: str, stderr: str = "") -> FixupResult:
        shutil.rmtree(obj_dir, ignore_errors=True)
        return FixupResult(None, src, False, attempts, error, stderr)

    try:
        all_flags = base + module_flags(fixup)
        src = fixup.prepare(code, ctx) if fixup is not None else code
        if not isinstance(src, str):
            raise FixupError(f"prepare returned {type(src).__name__}")
    except Exception as exc:  # noqa: BLE001
        return fail(code, 0, f"fixup raised {type(exc).__name__}")

    repair = getattr(fixup, "repair", None)
    stderr = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            proc = _gcc_compile(src, obj_path, compiler, all_flags)
        except subprocess.TimeoutExpired:
            return fail(src, attempt, "timeout")
        except FileNotFoundError:
            return fail(src, attempt, "compiler-not-found")
        if proc.returncode == 0 and obj_path.exists():
            return FixupResult(obj_path, src, True, attempt, None, proc.stderr)
        stderr = proc.stderr
        if repair is None or attempt == MAX_ATTEMPTS:
            break
        try:
            revised = repair(src, stderr, ctx)
        except Exception as exc:  # noqa: BLE001
            return fail(src, attempt, f"fixup raised {type(exc).__name__}", stderr)
        if not isinstance(revised, str) or revised == src:
            break
        src = revised
    return fail(src, attempt, _summarize_compiler_errors(stderr), stderr)
