"""
DecBench - Benchmarking suite for evaluating decompiler performance.

This package provides tools for:
- Compiling C projects with various optimization levels
- Running multiple decompilers on compiled binaries
- Computing metrics across categories (Faithful, Simple, Correct)
- Generating scoreboards and comparative analysis
"""

__version__ = "0.1.0"

from decbench.models.project import Project
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.models.metrics import MetricResult, CategoryScore
from decbench.models.scoreboard import Scoreboard, DecompilerScore

__all__ = [
    "Project",
    "DecompilationResult",
    "FunctionDecompilation",
    "MetricResult",
    "CategoryScore",
    "Scoreboard",
    "DecompilerScore",
]
