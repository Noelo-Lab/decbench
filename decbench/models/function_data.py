"""Per-function result data for the interactive HTML report.

These models persist the per-function metric values, perfect flags, and
labels so that the static HTML report can recompute aggregates client-side
when the user toggles labels and binaries on or off.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class FunctionRecord(BaseModel):
    """Per-function metric values and perfect flags across decompilers."""

    function: str = Field(..., description="Function name")
    values: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description="decompiler -> metric -> raw metric value",
    )
    perfects: dict[str, dict[str, bool]] = Field(
        default_factory=dict,
        description="decompiler -> metric -> whether the value is perfect",
    )
    labels: list[str] = Field(
        default_factory=list,
        description="Labels applied to this function",
    )


class BinaryGroup(BaseModel):
    """All functions for a single (project, opt level, binary) tuple."""

    project: str = Field(..., description="Project name")
    opt_level: str = Field(..., description="Optimization level (e.g. 'O2')")
    binary: str = Field(..., description="Binary name (stem)")
    labels: list[str] = Field(
        default_factory=list,
        description="Labels applied to this binary",
    )
    functions: list[FunctionRecord] = Field(
        default_factory=list,
        description="Per-function records for this binary",
    )


class FunctionData(BaseModel):
    """Top-level per-function dataset embedded in the HTML report."""

    schema_version: int = Field(default=1, description="Data schema version")
    decompilers: list[str] = Field(
        default_factory=list,
        description="All decompilers present in the dataset",
    )
    metrics: list[str] = Field(
        default_factory=list,
        description="All metrics present in the dataset",
    )
    perfect_values: dict[str, float] = Field(
        default_factory=dict,
        description="metric -> the value considered perfect",
    )
    groups: list[BinaryGroup] = Field(
        default_factory=list,
        description="Per-binary groups of function records",
    )

    def to_json(self, path: Path) -> None:
        """Serialize this dataset to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2)

    @classmethod
    def from_json(cls, path: Path) -> FunctionData:
        """Load a dataset from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
