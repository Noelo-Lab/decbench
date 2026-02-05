"""Configuration management for DecBench."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class DecBenchConfig(BaseModel):
    """Global configuration for DecBench."""

    # Paths
    results_dir: Path = Field(
        default=Path("results"),
        description="Default directory for results",
    )
    projects_dir: Path = Field(
        default=Path("projects"),
        description="Directory containing project configurations",
    )
    cache_dir: Path = Field(
        default=Path(".decbench_cache"),
        description="Directory for caching intermediate results",
    )

    # Parallelism
    default_workers: int | None = Field(
        default=None,
        description="Default number of workers (None for CPU count)",
    )

    # Decompiler configuration
    decompiler_timeout: float = Field(
        default=3600.0,
        description="Default timeout for decompilation in seconds",
    )
    function_timeout: float = Field(
        default=600.0,
        description="Default timeout per function in seconds",
    )

    # Metric configuration
    metric_timeout: float = Field(
        default=60.0,
        description="Default timeout for metric computation per function",
    )

    # Paths to external tools
    ghidra_path: str | None = Field(
        default=None,
        description="Path to Ghidra installation",
    )
    ida_path: str | None = Field(
        default=None,
        description="Path to IDA Pro installation",
    )

    @classmethod
    def from_toml(cls, path: Path) -> DecBenchConfig:
        """Load configuration from TOML file."""
        import toml

        if not path.exists():
            return cls()

        data = toml.load(path)
        return cls(**data)

    def to_toml(self, path: Path) -> None:
        """Save configuration to TOML file."""
        import toml

        data = self.model_dump(mode="json")
        # Convert Path objects to strings
        for key, value in data.items():
            if isinstance(value, Path):
                data[key] = str(value)

        with open(path, "w") as f:
            toml.dump(data, f)


def get_config(config_path: Path | None = None) -> DecBenchConfig:
    """Get the global configuration.

    Args:
        config_path: Optional path to config file

    Returns:
        DecBenchConfig instance
    """
    if config_path is None:
        # Check standard locations
        candidates = [
            Path("decbench.toml"),
            Path.home() / ".config" / "decbench" / "config.toml",
            Path.home() / ".decbench.toml",
        ]
        for path in candidates:
            if path.exists():
                return DecBenchConfig.from_toml(path)

        return DecBenchConfig()

    return DecBenchConfig.from_toml(config_path)
