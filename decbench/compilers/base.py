"""Base compiler interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CompileResult:
    """Result of compiling a source file."""

    source_path: Path
    object_path: Path | None = None
    preprocessed_path: Path | None = None

    success: bool = False
    error_message: str | None = None

    # Extracted metadata
    functions: list[tuple[str, int]] = field(default_factory=list)


class Compiler(ABC):
    """Abstract base class for compilers."""

    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this compiler is available."""
        ...

    @abstractmethod
    def compile(
        self,
        source_path: Path,
        output_dir: Path,
        optimization: str = "O2",
        extra_flags: list[str] | None = None,
        emit_preprocessed: bool = True,
    ) -> CompileResult:
        """Compile a source file.

        Args:
            source_path: Path to C source file
            output_dir: Directory for output files
            optimization: Optimization level (O0, O1, O2, O3)
            extra_flags: Additional compiler flags
            emit_preprocessed: Whether to emit preprocessed .i file

        Returns:
            CompileResult with paths and status
        """
        ...

    @abstractmethod
    def compile_project(
        self,
        project_dir: Path,
        output_dir: Path,
        optimization: str = "O2",
        source_pattern: str = "**/*.c",
        pre_commands: list[str] | None = None,
        make_command: str | None = None,
        extra_flags: list[str] | None = None,
    ) -> list[CompileResult]:
        """Compile an entire project.

        Args:
            project_dir: Root directory of the project
            output_dir: Directory for output files
            optimization: Optimization level
            source_pattern: Glob pattern for source files
            pre_commands: Commands to run before compilation (e.g., ./configure)
            make_command: Make command to use (if None, compile files directly)
            extra_flags: Additional compiler flags

        Returns:
            List of CompileResult for each source file
        """
        ...
