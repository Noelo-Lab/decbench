"""Base decompiler interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from decbench.models.decompilation import DecompilationResult


class DecompilerConfig(BaseModel):
    """Configuration for a decompiler."""

    # Timeouts
    function_timeout_seconds: float = Field(
        default=600.0,
        description="Timeout per function in seconds",
    )
    binary_timeout_seconds: float = Field(
        default=3600.0,
        description="Timeout per binary in seconds",
    )

    # Output options
    dump_line_mappings: bool = Field(
        default=True,
        description="Generate line-to-address mappings",
    )
    dump_early_metrics: bool = Field(
        default=True,
        description="Pre-compute metrics during decompilation",
    )

    # Decompiler-specific options
    extra_options: dict[str, Any] = Field(
        default_factory=dict,
        description="Decompiler-specific configuration options",
    )


class Decompiler(ABC):
    """Abstract base class for decompiler plugins.

    To create a new decompiler plugin:
    1. Subclass this class
    2. Implement all abstract methods
    3. Register with @register_decompiler decorator

    Example:
        @register_decompiler("my_decompiler")
        class MyDecompiler(Decompiler):
            name = "my_decompiler"
            display_name = "My Decompiler"

            def decompile_binary(self, binary_path, functions, output_dir):
                ...
    """

    # Class attributes to be overridden
    name: str = "base"
    display_name: str = "Base Decompiler"
    version: str | None = None

    def __init__(self, config: DecompilerConfig | None = None):
        """Initialize the decompiler.

        Args:
            config: Configuration for the decompiler
        """
        self.config = config or DecompilerConfig()

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this decompiler is available on the system.

        Returns:
            True if the decompiler can be used, False otherwise
        """
        ...

    @abstractmethod
    def get_version(self) -> str | None:
        """Get the version of the decompiler.

        Returns:
            Version string or None if unknown
        """
        ...

    @abstractmethod
    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary file.

        Args:
            binary_path: Path to the binary to decompile
            functions: Optional list of (function_name, address) to decompile.
                      If None, decompile all discovered functions.
            output_dir: Directory to write output files

        Returns:
            DecompilationResult with all function decompilations
        """
        ...

    def decompile_function(
        self,
        binary_path: Path,
        function_name: str,
        function_address: int,
    ) -> str | None:
        """Decompile a single function.

        Default implementation uses decompile_binary with single function.
        Override for more efficient single-function decompilation.

        Args:
            binary_path: Path to the binary
            function_name: Name of the function
            function_address: Address of the function

        Returns:
            Decompiled C code or None on failure
        """
        result = self.decompile_binary(
            binary_path,
            functions=[(function_name, function_address)],
        )

        if function_name in result.functions:
            return result.functions[function_name].decompiled_code

        return None

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions in a binary.

        Default implementation returns empty list.
        Override to provide function discovery.

        Args:
            binary_path: Path to the binary

        Returns:
            List of (function_name, address) tuples
        """
        return []

    def cleanup(self) -> None:
        """Clean up any resources used by the decompiler.

        Called after decompilation is complete.
        """
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
