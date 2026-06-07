"""Decompiler plugins for DecBench."""

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import DecompilerRegistry, register_decompiler

# Import plugin modules so @register_decompiler decorators run.
# declib_dec registers all backends (ida, ghidra, binja, angr); the heavy
# decompiler imports happen lazily inside each plugin.
try:
    from decbench.decompilers import declib_dec  # noqa: F401
except ImportError:
    pass

__all__ = [
    "Decompiler",
    "DecompilerConfig",
    "DecompilerRegistry",
    "register_decompiler",
]
