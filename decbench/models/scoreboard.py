"""Scoreboard models for displaying benchmark results."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from decbench.models.metrics import CategoryScore, MetricCategory


class CategoryBreakdown(BaseModel):
    """Detailed breakdown for a single category."""

    category: MetricCategory = Field(..., description="The category")

    # Per-decompiler scores
    scores: dict[str, CategoryScore] = Field(
        default_factory=dict,
        description="Category scores keyed by decompiler name",
    )

    # Rankings
    rankings: list[tuple[str, float]] = Field(
        default_factory=list,
        description="Decompilers ranked by score [(name, score), ...]",
    )

    # Category-specific display
    headline_format: str = Field(
        default="{value:.1f}%",
        description="Format string for headline display",
    )

    def compute_rankings(self) -> None:
        """Compute rankings from scores."""
        # Sort by weighted score (higher is better for final scores)
        ranked = sorted(
            self.scores.items(),
            key=lambda x: x[1].weighted_score,
            reverse=True,
        )
        self.rankings = [(name, score.weighted_score) for name, score in ranked]

        # Assign ranks
        for i, (name, _) in enumerate(self.rankings):
            self.scores[name].rank = i + 1


class DecompilerScore(BaseModel):
    """Complete score for a single decompiler."""

    name: str = Field(..., description="Decompiler name")
    version: str | None = Field(default=None, description="Decompiler version")

    # Category scores
    category_scores: dict[MetricCategory, CategoryScore] = Field(
        default_factory=dict,
        description="Scores for each category",
    )

    # Overall score
    overall_score: float = Field(
        default=0.0,
        description="Combined overall score",
    )
    overall_rank: int | None = Field(
        default=None,
        description="Overall rank among decompilers",
    )

    # Summary statistics
    total_functions_evaluated: int = Field(
        default=0,
        description="Total functions evaluated",
    )
    total_binaries_evaluated: int = Field(
        default=0,
        description="Total binaries evaluated",
    )

    # Metadata
    evaluation_time_seconds: float = Field(
        default=0.0,
        description="Total evaluation time",
    )

    def compute_overall_score(
        self,
        category_weights: dict[MetricCategory, float] | None = None,
    ) -> None:
        """Compute overall score from category scores."""
        if category_weights is None:
            # Equal weights by default
            category_weights = {cat: 1.0 for cat in MetricCategory}

        total_weight = sum(
            category_weights.get(cat, 0.0)
            for cat in self.category_scores
        )

        if total_weight == 0:
            self.overall_score = 0.0
            return

        weighted_sum = sum(
            self.category_scores[cat].weighted_score * category_weights.get(cat, 0.0)
            for cat in self.category_scores
        )
        self.overall_score = weighted_sum / total_weight


class Scoreboard(BaseModel):
    """Complete scoreboard with all results."""

    # Identity
    name: str = Field(
        default="DecBench Scoreboard",
        description="Name of this scoreboard",
    )
    description: str = Field(
        default="",
        description="Description of the benchmark",
    )
    version: str = Field(
        default="1.0",
        description="Scoreboard format version",
    )

    # Timestamp
    generated_at: datetime = Field(
        default_factory=datetime.now,
        description="When the scoreboard was generated",
    )

    # Configuration
    projects_evaluated: list[str] = Field(
        default_factory=list,
        description="List of project names included",
    )
    optimization_levels: list[str] = Field(
        default_factory=list,
        description="Optimization levels included",
    )
    decompilers: list[str] = Field(
        default_factory=list,
        description="Decompilers evaluated",
    )

    # Category configurations
    category_weights: dict[MetricCategory, float] = Field(
        default_factory=lambda: {cat: 1.0 for cat in MetricCategory},
        description="Weights for each category in overall score",
    )

    # Results
    decompiler_scores: dict[str, DecompilerScore] = Field(
        default_factory=dict,
        description="Complete scores keyed by decompiler name",
    )
    category_breakdowns: dict[MetricCategory, CategoryBreakdown] = Field(
        default_factory=dict,
        description="Detailed breakdown for each category",
    )

    # Summary statistics
    total_functions: int = Field(
        default=0,
        description="Total unique functions evaluated",
    )
    total_binaries: int = Field(
        default=0,
        description="Total binaries evaluated",
    )

    # Raw data reference
    raw_data_path: Path | None = Field(
        default=None,
        description="Path to raw measurement data",
    )

    def get_category_rankings(self, category: MetricCategory) -> list[tuple[str, float, str]]:
        """Get rankings for a category with display strings.

        Returns:
            List of (decompiler_name, score, display_string) tuples
        """
        if category not in self.category_breakdowns:
            return []

        breakdown = self.category_breakdowns[category]
        result = []

        for name, score in breakdown.rankings:
            cat_score = breakdown.scores[name]
            display = cat_score.headline_display or f"{score:.1f}"
            result.append((name, score, display))

        return result

    def get_overall_rankings(self) -> list[tuple[str, float]]:
        """Get overall rankings across all categories."""
        ranked = sorted(
            self.decompiler_scores.items(),
            key=lambda x: x[1].overall_score,
            reverse=True,
        )
        return [(name, score.overall_score) for name, score in ranked]

    def to_display_dict(self) -> dict[str, Any]:
        """Convert to a display-friendly dictionary."""
        result = {
            "name": self.name,
            "generated_at": self.generated_at.isoformat(),
            "projects": self.projects_evaluated,
            "decompilers": self.decompilers,
            "total_functions": self.total_functions,
            "categories": {},
        }

        for category in MetricCategory:
            if category not in self.category_breakdowns:
                continue

            rankings = self.get_category_rankings(category)
            result["categories"][category.value] = {
                "name": category.value.title(),
                "rankings": [
                    {"decompiler": name, "score": score, "display": display}
                    for name, score, display in rankings
                ],
            }

        result["overall"] = [
            {"decompiler": name, "score": score}
            for name, score in self.get_overall_rankings()
        ]

        return result

    def to_toml(self, path: Path) -> None:
        """Save scoreboard to TOML file."""
        import toml

        data = self.model_dump(mode="json", exclude={"raw_data_path"})

        # Convert enums to strings
        data["category_weights"] = {
            k.value if hasattr(k, "value") else k: v
            for k, v in data.get("category_weights", {}).items()
        }

        with open(path, "w") as f:
            toml.dump(data, f)

    @classmethod
    def from_toml(cls, path: Path) -> Scoreboard:
        """Load scoreboard from TOML file."""
        import toml

        data = toml.load(path)

        # Convert string keys back to enums where needed
        if "category_weights" in data:
            data["category_weights"] = {
                MetricCategory(k): v for k, v in data["category_weights"].items()
            }

        return cls(**data)

    def render_text(self) -> str:
        """Render scoreboard as formatted text."""
        lines = []
        lines.append(f"{'=' * 60}")
        lines.append(f"  {self.name}")
        lines.append(f"  Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"  Functions: {self.total_functions:,} | Binaries: {self.total_binaries:,}")
        lines.append(f"{'=' * 60}")
        lines.append("")

        for category in MetricCategory:
            if category not in self.category_breakdowns:
                continue

            lines.append(f"{category.value.title()}:")
            rankings = self.get_category_rankings(category)

            for i, (name, score, display) in enumerate(rankings):
                prefix = "  " if i > 0 else "  "
                lines.append(f"{prefix}{name} - {display}")

            lines.append("")

        return "\n".join(lines)
