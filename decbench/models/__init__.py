"""Data models for DecBench."""

from decbench.models.project import Project, ProjectConfig, CompilationConfig
from decbench.models.decompilation import (
    DecompilationResult,
    FunctionDecompilation,
    DecompilerMetadata,
)
from decbench.models.metrics import (
    MetricResult,
    MetricValue,
    CategoryScore,
    FunctionMetrics,
)
from decbench.models.scoreboard import (
    Scoreboard,
    DecompilerScore,
    CategoryBreakdown,
)

__all__ = [
    # Project models
    "Project",
    "ProjectConfig",
    "CompilationConfig",
    # Decompilation models
    "DecompilationResult",
    "FunctionDecompilation",
    "DecompilerMetadata",
    # Metric models
    "MetricResult",
    "MetricValue",
    "CategoryScore",
    "FunctionMetrics",
    # Scoreboard models
    "Scoreboard",
    "DecompilerScore",
    "CategoryBreakdown",
]
