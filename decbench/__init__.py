"""
DecBench - Benchmarking suite for evaluating decompiler performance.

Three-metric evaluation:
- Structural Correctness (GED): CFG edit distance
- Type Correctness: Variable type recovery accuracy
- Recompilation Bytematch: Assembly similarity after recompilation
"""

# Two-digit versioning (major.minor). Must stay ABOVE the imports below:
# models.scoreboard reads it at import time for the Scoreboard/footer version.
__version__ = "1.1"

from decbench.models.project import Project
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.models.metrics import MetricResult
from decbench.models.scoreboard import Scoreboard, DecompilerScore

__all__ = [
    "Project",
    "DecompilationResult",
    "FunctionDecompilation",
    "MetricResult",
    "Scoreboard",
    "DecompilerScore",
]
