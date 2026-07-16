"""Scoreboard models for displaying benchmark results."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class MetricScore(BaseModel):
    """Score for a single metric for one decompiler."""

    metric_name: str = Field(..., description="Name of the metric")
    decompiler_name: str = Field(..., description="Decompiler name")

    perfect_count: int = Field(default=0, description="Functions with perfect score")
    total_count: int = Field(default=0, description="Total functions evaluated")
    perfect_percentage: float = Field(default=0.0, description="Percentage with perfect score")

    mean: float = Field(default=0.0, description="Mean metric value")
    median: float = Field(default=0.0, description="Median metric value")

    rank: int | None = Field(default=None, description="Rank among decompilers")


class DecompilerScore(BaseModel):
    """Complete score for a single decompiler."""

    name: str = Field(..., description="Decompiler name")
    version: str | None = Field(default=None, description="Decompiler version")

    metric_scores: dict[str, MetricScore] = Field(
        default_factory=dict,
        description="Scores for each metric",
    )

    overall_perfect_count: int = Field(
        default=0,
        description="Union: functions perfect on AT LEAST ONE metric",
    )
    overall_total_count: int = Field(default=0, description="Total functions evaluated")
    overall_perfect_percentage: float = Field(
        default=0.0,
        description="Union: percentage of functions perfect on at least one metric",
    )
    overall_rank: int | None = Field(default=None, description="Union rank")

    total_functions_evaluated: int = Field(default=0)
    total_binaries_evaluated: int = Field(default=0)
    evaluation_time_seconds: float = Field(default=0.0)


class Scoreboard(BaseModel):
    """Complete scoreboard with all results."""

    name: str = Field(default="DecBench Scoreboard")
    description: str = Field(default="")
    version: str = Field(default="2.0")

    generated_at: datetime = Field(default_factory=datetime.now)

    projects_evaluated: list[str] = Field(default_factory=list)
    optimization_levels: list[str] = Field(default_factory=list)
    decompilers: list[str] = Field(default_factory=list)
    metrics: list[str] = Field(default_factory=list)

    decompiler_scores: dict[str, DecompilerScore] = Field(default_factory=dict)

    total_functions: int = Field(default=0)
    total_binaries: int = Field(default=0)

    raw_data_path: Path | None = Field(default=None)

    def get_metric_rankings(self, metric_name: str) -> list[tuple[str, float]]:
        """Get decompiler rankings for a specific metric (by perfect_percentage)."""
        ranked = []
        for dec_name, dec_score in self.decompiler_scores.items():
            if metric_name in dec_score.metric_scores:
                ms = dec_score.metric_scores[metric_name]
                ranked.append((dec_name, ms.perfect_percentage))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def get_overall_rankings(self) -> list[tuple[str, float]]:
        """Get overall rankings (by overall_perfect_percentage)."""
        ranked = sorted(
            self.decompiler_scores.items(),
            key=lambda x: x[1].overall_perfect_percentage,
            reverse=True,
        )
        return [(name, score.overall_perfect_percentage) for name, score in ranked]

    def to_display_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "generated_at": self.generated_at.isoformat(),
            "projects": self.projects_evaluated,
            "decompilers": self.decompilers,
            "total_functions": self.total_functions,
            "metrics": {},
        }

        for metric_name in self.metrics:
            rankings = self.get_metric_rankings(metric_name)
            result["metrics"][metric_name] = {
                "name": metric_name,
                "rankings": [
                    {"decompiler": name, "perfect_percentage": pct}
                    for name, pct in rankings
                ],
            }

        result["overall"] = [
            {"decompiler": name, "perfect_percentage": pct}
            for name, pct in self.get_overall_rankings()
        ]

        return result

    def to_toml(self, path: Path) -> None:
        import toml

        data = self.model_dump(mode="json", exclude={"raw_data_path"})

        with open(path, "w") as f:
            toml.dump(data, f)

    @classmethod
    def from_toml(cls, path: Path) -> Scoreboard:
        import toml

        data = toml.load(path)
        return cls(**data)

    def render_text(self) -> str:
        lines = []
        lines.append(f"{'=' * 60}")
        lines.append(f"  {self.name}")
        lines.append(f"  Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"  Functions: {self.total_functions:,} | Binaries: {self.total_binaries:,}")
        lines.append(f"{'=' * 60}")
        lines.append("")

        for metric_name in self.metrics:
            lines.append(f"{metric_name.upper()}:")
            lines.append("-" * 40)
            rankings = self.get_metric_rankings(metric_name)
            for i, (dec_name, pct) in enumerate(rankings):
                marker = ">" if i == 0 else " "
                lines.append(f"  {marker} {dec_name:20} {pct:>10.1f}%")
            lines.append("")

        lines.append("UNION (perfect on at least one metric):")
        lines.append("-" * 40)
        for i, (dec_name, pct) in enumerate(self.get_overall_rankings()):
            marker = ">" if i == 0 else " "
            lines.append(f"  {marker} {dec_name:20} {pct:>10.1f}%")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
