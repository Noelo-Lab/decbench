"""Per-decompiler compilability fixups for the byte-match metric.

Each module in ``generated/`` (``<decompiler>.py``, ``-`` spelled ``_``) adapts
ONE decompiler's C dialect to gcc. None is hand-written: every module is produced
by the same fixup agent, from the same prompt (``PROMPT.md``), under the same
time budget, by ``scripts/fixup_agent.py``. Regenerating one means
regenerating all of them the same way.

A module may define:

``FLAGS: list[str]``
    Extra compiler flags, restricted to diagnostics and language dialect
    (:func:`module_flags` enforces the allowlist).
``prepare(code: str, ctx: FixupContext) -> str``
    Required. Returns the translation unit to compile for one function.
``repair(source: str, stderr: str, ctx: FixupContext) -> str | None``
    Optional. Given the last translation unit and gcc's stderr, returns a
    revised unit, or ``None`` to stop.

The harness (:func:`decbench.metrics.fixup.compile_with_fixup`) owns every
compile; modules only transform text.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import ModuleType

GENERATED = Path(__file__).parent / "generated"
_ALLOWED_FLAG = re.compile(
    r"^-(?:W(?![apl],)[\w=,+-]+|[DU]\w\S*|std=[\w+]+|fms-extensions|fplan9-extensions)$"
)


class FixupError(ValueError):
    """A fixup module broke its contract."""


@dataclass(frozen=True)
class FixupContext:
    """What a fixup module may know about the function it is fixing.

    ``siblings`` maps every function name the same decompiler emitted for the
    same binary to its code (the target included). ``binary_key`` identifies
    that sibling set, so a module can memoize per-binary analysis. ``flags``
    are the neutral compile flags, read-only.
    """

    func_name: str
    siblings: Mapping[str, str]
    binary_key: str
    compiler: str
    flags: tuple[str, ...]


def module_name(decompiler: str) -> str:
    """The module basename for a decompiler id (``name@version`` shares ``name``)."""
    return decompiler.split("@", 1)[0].replace("-", "_")


def module_path(decompiler: str | None) -> Path | None:
    """Where ``decompiler``'s fixup module lives, or None if it has none."""
    if not decompiler:
        return None
    path = GENERATED / f"{module_name(decompiler)}.py"
    return path if path.is_file() else None


@cache
def load(decompiler: str | None) -> ModuleType | None:
    """The fixup module for ``decompiler``, or None if it has none."""
    if module_path(decompiler) is None:
        return None
    return importlib.import_module(f"{__name__}.generated.{module_name(decompiler)}")


def load_path(path: Path) -> ModuleType:
    """Import a fixup module from an arbitrary file (the workbench's candidate)."""
    spec = importlib.util.spec_from_file_location(f"decbench_fixup_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise FixupError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "prepare", None)):
        raise FixupError(f"{path} defines no prepare()")
    return module


def module_flags(module: ModuleType | None) -> list[str]:
    """``module.FLAGS``, rejecting anything outside the diagnostics/dialect allowlist."""
    flags = list(getattr(module, "FLAGS", []) or [])
    bad = [f for f in flags if not isinstance(f, str) or not _ALLOWED_FLAG.match(f)]
    if bad:
        raise FixupError(f"disallowed fixup flags: {bad}")
    return flags


@cache
def fingerprint(decompiler: str | None) -> str:
    """Content hash of a decompiler's fixup module ("" without one), for cache keys."""
    module = load(decompiler)
    if module is None or module.__file__ is None:
        return ""
    return hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()


def binary_key(siblings: Mapping[str, str]) -> str:
    """Stable digest of one binary's sibling set."""
    h = hashlib.sha256()
    for name in sorted(siblings):
        h.update(name.encode())
        h.update(b"\0")
        h.update(siblings[name].encode(errors="replace"))
        h.update(b"\0")
    return h.hexdigest()
