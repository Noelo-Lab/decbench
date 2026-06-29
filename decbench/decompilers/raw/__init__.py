"""Raw (declib-free) decompiler backends.

These backends drive the native decompiler APIs directly — angr's
``analyses.Decompiler``, Ghidra via ``pyghidra``, IDA's Hex-Rays via
``idalib``/``idapro``, and Binary Ninja's headless API — instead of going
through the unified ``declib`` interface. They produce the exact same
:class:`~decbench.models.decompilation.DecompilationResult` shape as
``declib_dec`` (ELF-file-space addresses, ``VariableInfo`` lists, line
mappings, gotos/bools metadata).

Importing this package registers the raw backends under the canonical
``angr`` / ``ghidra`` / ``ida`` / ``binja`` names. The declib-backed
implementations remain available for comparison under ``angr-declib`` etc.
"""

from __future__ import annotations

# Import each backend module so the @register_decompiler decorators run.
# Heavy native imports (angr, pyghidra, idapro, binaryninja) happen lazily
# inside each plugin, so importing this package is cheap and never fails on
# a missing decompiler.
from decbench.decompilers.raw import (
    angr_raw,  # noqa: F401
    binja_raw,  # noqa: F401
    ghidra_raw,  # noqa: F401
    ida_raw,  # noqa: F401
    kuna_raw,  # noqa: F401
)

__all__ = ["angr_raw", "ghidra_raw", "ida_raw", "binja_raw", "kuna_raw"]
