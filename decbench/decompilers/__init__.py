"""Decompiler plugins for DecBench."""

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import DecompilerRegistry, register_decompiler

__all__ = [
    "Decompiler",
    "DecompilerConfig",
    "DecompilerRegistry",
    "register_decompiler",
]
