"""Decompiler plugins for DecBench."""

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import DecompilerRegistry, register_decompiler

# Import plugin modules so @register_decompiler decorators run
try:
    from decbench.decompilers import angr_dec  # noqa: F401
except ImportError:
    pass

try:
    from decbench.decompilers import ghidra_dec  # noqa: F401
except ImportError:
    pass

try:
    from decbench.decompilers import ida_dec  # noqa: F401
except ImportError:
    pass

__all__ = [
    "Decompiler",
    "DecompilerConfig",
    "DecompilerRegistry",
    "register_decompiler",
]
