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
    distances: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description="decompiler -> metric -> raw EDIT DISTANCE to a perfect result "
        "(lower is better): GED = the graph edit distance itself; type_match = "
        "number of type-flips to exact (fp+fn); byte_match = number of changed "
        "assembly lines. Powers the report's 'distance' view; absent for a "
        "(decompiler, metric) with no computed value.",
    )
    decompiled: dict[str, bool] = Field(
        default_factory=dict,
        description="decompiler -> whether it successfully produced output for "
        "this function (False = decompile failed / timed out). The denominator "
        "for every metric is the set of functions a decompiler decompiled, so "
        "all metrics share one denominator per decompiler; a missing metric on a "
        "decompiled function counts as not-perfect.",
    )
    labels: list[str] = Field(
        default_factory=list,
        description="Labels applied to this function",
    )
    size: int | None = Field(
        default=None,
        description="Representative decompiled line count (for size-based "
        "subsetting and the 'large' auto label)",
    )
    datasets: list[str] = Field(
        default_factory=list,
        description="Names of the dataset presets this function belongs to "
        "(e.g. 'unoptimized', 'optimized', 'inlined', 'large', 'sample-set'); "
        "drives the report's single dataset selector instead of many ad-hoc toggles",
    )


class HardestEntry(BaseModel):
    """A single 'hardest function' row: a function with a poor metric value.

    Precomputed server-side (bounded count) so the report can show a
    'Hall of Shame' of the functions decompilers struggle with most,
    including the decompiled (and, when available, source) code.
    """

    metric: str = Field(..., description="Metric this entry is ranked under")
    decompiler: str = Field(..., description="Decompiler id (may be name@version)")
    project: str = Field(...)
    opt_level: str = Field(...)
    binary: str = Field(...)
    function: str = Field(...)
    value: float = Field(..., description="Raw metric value (worse = harder)")
    perfect_value: float = Field(..., description="The value considered perfect")
    size: int | None = Field(default=None, description="Decompiled line count")
    labels: list[str] = Field(default_factory=list)
    decompiled_code: str | None = Field(default=None, description="Decompiled C for this function")
    source_code: str | None = Field(
        default=None, description="Best-effort source C for this function"
    )


class SampleEntry(BaseModel):
    """A curated function shown in the report's side-by-side 'View' page.

    Carries the original source next to each decompiler's output (plus per-metric
    scores) so a reader can eyeball, e.g., Ghidra's recovery against the truth.
    Bounded server-side to three difficulty tiers of ~100 functions (see
    :func:`decbench.scoring.report_extras.build_samples` and
    :mod:`decbench.scoring.view_samples`) to keep the embedded report small.
    """

    project: str = Field(...)
    opt_level: str = Field(...)
    binary: str = Field(...)
    function: str = Field(...)
    size: int | None = Field(default=None, description="Decompiled line count")
    labels: list[str] = Field(default_factory=list)
    difficulty: str | None = Field(
        default=None,
        description="Difficulty tier (easy/medium/hard) derived from cross-"
        "decompiler GED agreement; None on samples written before the tiers "
        "existed (the View page then shows them untiered)",
    )
    source_code: str | None = Field(default=None, description="Original source C")
    source_status: str | None = Field(
        default=None,
        description="Provenance/diagnostic for source_code: '' or None = extracted "
        "from a real .c; 'preprocessed' = recovered from a .i (macros expanded); "
        "'binary_not_found'/'no_source_files'/'func_not_in_sources'/'extract_failed' "
        "= why source_code is missing. Default None keeps pre-field JSON loadable.",
    )
    decompiled: dict[str, str] = Field(
        default_factory=dict, description="decompiler id -> decompiled C"
    )
    values: dict[str, dict[str, float]] = Field(
        default_factory=dict, description="decompiler -> metric -> value"
    )
    perfects: dict[str, dict[str, bool]] = Field(
        default_factory=dict, description="decompiler -> metric -> perfect flag"
    )


class DatasetPreset(BaseModel):
    """A named, selectable view of the dataset shown in the report.

    Replaces the report's many label/binary toggles with a small fixed set of
    curated views (unoptimized / optimized / inlined / large / sample-set).
    Membership per function is precomputed server-side (see
    :mod:`decbench.scoring.datasets`) and stored on
    :attr:`FunctionRecord.datasets`.

    Only :attr:`name` is meaningful for new data: the presentation is owned by
    ``decbench/rendering/content/datasets.toml`` and joined on at render time.
    :attr:`label` / :attr:`description` remain so that datasets written before that
    split still carry their own text and still render (see
    :func:`decbench.rendering.aggregate.resolve_presets`).
    """

    name: str = Field(..., description="Stable id used in FunctionRecord.datasets")
    label: str = Field(default="", description="Display label (legacy; see class docstring)")
    description: str = Field(
        default="", description="One-line description (legacy; see class docstring)"
    )


class HistoryPoint(BaseModel):
    """One (decompiler, version, date) sample of aggregate scores.

    Powers the historical line charts: how a decompiler's metric scores
    change across versions/time. Built by ingesting multiple scoreboards.
    """

    decompiler: str = Field(..., description="Base decompiler name, e.g. 'ghidra'")
    version: str = Field(..., description="Version label, e.g. '11.3' or '12.1'")
    date: str | None = Field(default=None, description="ISO date this version is associated with")
    scores: dict[str, float] = Field(
        default_factory=dict,
        description="metric -> perfect percentage at this version",
    )
    overall: float = Field(
        default=0.0,
        description="Union (perfect on at least one metric) percentage; points ingested "
        "from scoreboards older than the Union change carry the old all-metrics Overall",
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

    schema_version: int = Field(default=2, description="Data schema version")
    decompilers: list[str] = Field(
        default_factory=list,
        description="All decompilers present in the dataset (ids; may be name@version)",
    )
    decompiler_versions: dict[str, str] = Field(
        default_factory=dict,
        description="decompiler id -> human version label (for display)",
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
    dataset_presets: list[DatasetPreset] = Field(
        default_factory=list,
        description="The selectable dataset views "
        "(unoptimized/optimized/inlined/large/sample-set)",
    )
    hardest: list[HardestEntry] = Field(
        default_factory=list,
        description="Precomputed 'hardest functions' (worst scores) with code",
    )
    samples: list[SampleEntry] = Field(
        default_factory=list,
        description="Curated functions with source + per-decompiler output for "
        "the side-by-side Compare view",
    )
    compile_rates: dict[str, float] = Field(
        default_factory=dict,
        description="decompiler id -> fraction of functions whose decompilation "
        "recompiles (byte-match compilability), shown on the Metrics page",
    )
    dataset_info: dict = Field(
        default_factory=dict,
        description="Dataset overview for the About/Dataset page: total source "
        "lines of code, per-project LOC, and Joern source-parse failure rates "
        "(how much of the GED pipeline fails due to our own tooling). Software-"
        "type categories are derived client-side from per-binary labels.",
    )
    history: list[HistoryPoint] = Field(
        default_factory=list,
        description="Historical score samples across decompiler versions/time",
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
