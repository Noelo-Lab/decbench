"""Native decompiler backends.

These backends drive the native decompiler APIs directly — angr's
``analyses.Decompiler``, Ghidra via ``pyghidra``, IDA's Hex-Rays via
``idalib``/``idapro``, and Binary Ninja's headless API. They all produce the
shared :class:`~decbench.models.decompilation.DecompilationResult` shape with
ELF-file-space addresses, ``VariableInfo`` lists, line mappings, and structure
metadata.

Importing this package registers the raw backends under the canonical
``angr`` / ``ghidra`` / ``ida`` / ``binja`` names.
"""

from __future__ import annotations

# Imported for their @register_decompiler side effects. The heavy native imports
# happen lazily inside each plugin, so a missing decompiler never breaks this.
from decbench.decompilers.raw import (
    angr_raw,  # noqa: F401
    binja_raw,  # noqa: F401
    dewolf_raw,  # noqa: F401
    ghidra_raw,  # noqa: F401
    glaurung_raw,  # noqa: F401
    ida_raw,  # noqa: F401
    kuna_raw,  # noqa: F401
    manifold_raw,  # noqa: F401
)

__all__ = [
    "angr_raw",
    "ghidra_raw",
    "ida_raw",
    "binja_raw",
    "kuna_raw",
    "dewolf_raw",
    "manifold_raw",
    "glaurung_raw",
]
