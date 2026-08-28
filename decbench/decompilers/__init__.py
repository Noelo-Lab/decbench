"""Decompiler plugins for DecBench."""

import contextlib

from decbench.decompilers import external  # noqa: F401  (registers the external ids)
from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import DecompilerRegistry, register_decompiler

# Imported for their @register_decompiler side effects. Heavy decompiler imports
# happen lazily inside each plugin, so these never fail on a missing backend.
with contextlib.suppress(ImportError):
    from decbench.decompilers import declib_dec  # noqa: F401

with contextlib.suppress(ImportError):
    from decbench.decompilers import raw  # noqa: F401

with contextlib.suppress(ImportError):
    from decbench.decompilers import dockerized  # noqa: F401

with contextlib.suppress(ImportError):
    from decbench.decompilers import llm_dec  # noqa: F401

__all__ = [
    "Decompiler",
    "DecompilerConfig",
    "DecompilerRegistry",
    "register_decompiler",
]
