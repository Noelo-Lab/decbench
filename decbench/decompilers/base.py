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

    function_timeout_seconds: float = Field(
        default=600.0,
        description="Timeout per function in seconds",
    )
    binary_timeout_seconds: float = Field(
        default=3600.0,
        description="Timeout per binary in seconds",
    )

    dump_line_mappings: bool = Field(
        default=True,
        description="Generate line-to-address mappings",
    )
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

    name: str = "base"
    display_name: str = "Base Decompiler"
    version: str | None = None
    # False for a column DecBench cannot produce itself — an external submission
    # scored through `decbench evalkit ingest`. See decompilers/external.py.
    runnable: bool = True

    def __init__(self, config: DecompilerConfig | None = None):
        """Initialize the decompiler.

        Args:
            config: Configuration for the decompiler
        """
        self.config = config or DecompilerConfig()
        # Set by the registry from a ``name@version`` spec. ``requested_version`` is the
        # pinned label; ``get_version()`` reports the realized version.
        self.requested_version: str | None = None
        self._spec_id: str | None = None

    @property
    def id(self) -> str:
        """Canonical id used as this decompiler's key in results/scoreboards.

        ``name`` when unversioned, ``name@version`` when a version was pinned.
        """
        from decbench.decompilers.spec import make_id

        if self._spec_id is not None:
            return self._spec_id
        return make_id(self.name, self.requested_version)

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

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
