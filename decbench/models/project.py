"""Project and compilation configuration models."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class OptimizationLevel(str, Enum):
    """Compiler optimization levels."""
    O0 = "O0"
    O1 = "O1"
    O2 = "O2"
    O3 = "O3"
    Os = "Os"
    Oz = "Oz"


class RemoteType(str, Enum):
    """Source remote types."""
    GIT = "git"
    TAR = "tar"
    LOCAL = "local"


class CompilationConfig(BaseModel):
    """Configuration for compiling a project."""

    optimization_levels: list[OptimizationLevel] = Field(
        default=[OptimizationLevel.O2],
        description="Optimization levels to compile with",
    )
    base_flags: list[str] = Field(
        default=[
            "-g", "-fno-inline", "-fno-builtin", "-save-temps=obj"
        ],
        description="Base compiler flags applied to all compilations",
    )
    extra_flags: list[str] = Field(
        default=[],
        description="Additional compiler flags",
    )
    c_compiler: str = Field(default="gcc", description="C compiler to use")
    cpp_compiler: str = Field(default="g++", description="C++ compiler to use")
    emit_preprocessed: bool = Field(
        default=True,
        description="Whether to emit preprocessed C code (.i files)",
    )


class ProjectConfig(BaseModel):
    """Configuration for a project to be compiled and evaluated."""

    # Identity
    name: str = Field(..., description="Unique project identifier")
    version: str | None = Field(default=None, description="Version tag or commit")

    # Source location
    source_remote: str | None = Field(
        default=None,
        description="Remote URL for source (git URL or tar URL)",
    )
    remote_type: RemoteType = Field(
        default=RemoteType.LOCAL,
        description="Type of remote source",
    )
    local_path: Path | None = Field(
        default=None,
        description="Local path if remote_type is LOCAL",
    )

    # Build configuration
    package_dir: str | None = Field(
        default=None,
        description="Directory name after extraction/clone",
    )
    source_dir: str = Field(
        default="src",
        description="Subdirectory containing source files",
    )

    # Build commands
    post_download_cmds: list[str] = Field(
        default=[],
        description="Commands to run after downloading source",
    )
    pre_make_cmds: list[str] = Field(
        default=[],
        description="Commands to run before make (e.g., ./configure)",
    )
    make_cmd: str | None = Field(
        default=None,
        description="Build command (e.g., 'make'). None to compile files individually.",
    )
    post_make_cmds: list[str] = Field(
        default=[],
        description="Commands to run after make",
    )

    # Options
    apply_patch: str | None = Field(
        default=None,
        description="Patch file to apply after download",
    )
    skip_compilation: bool = Field(
        default=False,
        description="Skip compilation (use pre-built binaries)",
    )
    subset_files: list[str] | None = Field(
        default=None,
        description="Only compile these specific files",
    )

    @field_validator("local_path", mode="before")
    @classmethod
    def convert_path(cls, v) -> Path | None:
        if v is not None and not isinstance(v, Path):
            return Path(v)
        return v


class Project(BaseModel):
    """A complete project with its compilation configuration."""

    config: ProjectConfig = Field(..., description="Project configuration")
    compilation: CompilationConfig = Field(
        default_factory=CompilationConfig,
        description="Compilation configuration",
    )

    # Runtime state (not serialized to config)
    compiled_binaries: dict[OptimizationLevel, list[Path]] = Field(
        default_factory=dict,
        exclude=True,
        description="Paths to compiled binaries by optimization level",
    )
    preprocessed_sources: dict[OptimizationLevel, dict[str, Path]] = Field(
        default_factory=dict,
        exclude=True,
        description="Paths to preprocessed .i files by optimization level",
    )

    @property
    def name(self) -> str:
        return self.config.name

    @classmethod
    def from_toml(cls, path: Path) -> Project:
        """Load a project from a TOML configuration file."""
        import toml

        data = toml.load(path)

        # Extract compilation config if present
        compilation_data = data.pop("compilation", {})

        return cls(
            config=ProjectConfig(**data),
            compilation=CompilationConfig(**compilation_data),
        )

    def to_toml(self, path: Path) -> None:
        """Save project configuration to a TOML file."""
        import toml

        data = self.config.model_dump(exclude_none=True, mode="json")
        data["compilation"] = self.compilation.model_dump(exclude_none=True, mode="json")

        with open(path, "w") as f:
            toml.dump(data, f)
