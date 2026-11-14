"""Single-attempt compilation for the byte-match metric (legacy fixup API)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}

_DIAGNOSTIC_LINE = re.compile(r"^(?:.*?:\s*)?((?:fatal )?error):\s*(.+)$", re.MULTILINE)
_DIAGNOSTIC_CLASS = re.compile(r"\[(-W[^\]\s]+)\]")
_DIAGNOSTIC_QUOTED = re.compile(r"'[^'\n]*'|‘[^’\n]*’|“[^”\n]*”|\"[^\"\n]*\"")
_DIAGNOSTIC_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:)?[/\\][^\s:]+")
_DIAGNOSTIC_SOURCE_EXCERPT = re.compile(r"^\s*\d+\s*\|")
_DIAGNOSTIC_LIMIT = 400


@dataclass
class FixupResult:
    """Outcome of compiling the supplied C without repairs."""

    obj_path: Path | None
    source: str
    compilable: bool
    iterations: int
    injected: list[str] = field(default_factory=list)
    error: str | None = None


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


def _gcc_compile(
    src: str, obj_path: Path, compiler: str, flags: list[str]
) -> subprocess.CompletedProcess[str]:
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
    """Compile the supplied C once without sanitization or guessed declarations.

    SDK declarations and helpers must already be in ``code``. The caller owns
    the successful object's temporary directory and must remove it.
    """
    if flags is None:
        flags = ["-O2", "-c", "-fno-builtin"]
    flags = [f for f in flags if f != "-w"]
    if not _has_language_mode(flags):
        flags.append("-std=gnu17")
    flags.extend(
        [
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=int-conversion",
        ]
    )

    obj_dir = Path(tempfile.mkdtemp(prefix="decbench_bm_"))
    obj_path = obj_dir / f"{func_name}.o"
    try:
        proc = _gcc_compile(code, obj_path, compiler, flags)
    except subprocess.TimeoutExpired:
        error = "timeout"
    except FileNotFoundError:
        error = "compiler-not-found"
    else:
        if proc.returncode == 0 and obj_path.exists():
            return FixupResult(obj_path, code, True, 1)
        error = _summarize_compiler_errors(proc.stderr)

    shutil.rmtree(obj_dir, ignore_errors=True)
    return FixupResult(None, code, False, 1, [], error)
