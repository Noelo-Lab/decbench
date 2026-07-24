"""Decompilation result models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class LineMapping(BaseModel):
    """Maps decompiler output lines to source addresses."""

    line_number: int = Field(..., description="Line number in decompiler output")
    addresses: list[int] = Field(
        default_factory=list,
        description="Binary addresses corresponding to this line",
    )


class VariableInfo(BaseModel):
    """Structured variable info recovered by a decompiler.

    Stack offsets are in declib's canonical (lifted) stack-offset space,
    which is rbp-relative-ish with locals at negative offsets. The
    type_match metric calibrates against DWARF offsets at compare time.
    """

    name: str = Field(default="", description="Variable name in decompiled output")
    type: str = Field(default="", description="Variable type as a C type string")
    stack_offset: int | None = Field(
        default=None,
        description="Stack offset (declib-lifted); None for register vars/args",
    )
    size: int | None = Field(default=None, description="Size in bytes")
    kind: str = Field(default="stack", description="'stack' or 'arg'")
    arg_index: int | None = Field(
        default=None,
        description="Positional index for function arguments (ABI order)",
    )


class FunctionDecompilation(BaseModel):
    """Decompilation result for a single function."""

    name: str = Field(..., description="Function name")
    address: int = Field(..., description="Function start address in binary")
    decompiled_code: str = Field(..., description="Decompiled C code")
    line_count: int = Field(default=0, description="Number of lines in decompilation")

    # Line mappings for CFG reconstruction
    line_mappings: list[LineMapping] = Field(
        default_factory=list,
        description="Line to address mappings",
    )

    # Structured variable info (stack vars + args) for type matching
    variables: list[VariableInfo] = Field(
        default_factory=list,
        description="Recovered stack variables and function arguments",
    )

    # Pre-computed metadata (optional, computed during decompilation)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata (gotos, bools, func_calls, etc.)",
    )

    # Structured cost capture (optional — both default None so artifacts written
    # before these fields existed still load). Feeds the data page's cost section
    # via decbench.scoring.cost, which prefers these over the trace/artifact scans.
    time_seconds: float | None = Field(
        default=None,
        description="Wall time spent decompiling THIS function, when the backend "
        "measures per-function (the LLM agents: one agent call per function, "
        "including tool use). None for batch backends, whose per-function rate "
        "is amortized from DecompilerMetadata.total_time_seconds.",
    )
    llm_tokens: dict[str, int] | None = Field(
        default=None,
        description="Normalized token usage for this function's agent call "
        "(input / cached_input / cache_write / output — see "
        "decbench.scoring.cost.parse_session_tokens). None for non-LLM backends "
        "or when the session log was unavailable/unparseable.",
    )

    @property
    def has_gotos(self) -> bool:
        return self.metadata.get("gotos", 0) > 0

    @property
    def goto_count(self) -> int:
        return self.metadata.get("gotos", 0)


class DecompilerMetadata(BaseModel):
    """Metadata about a decompiler run."""

    decompiler_name: str = Field(..., description="Name of the decompiler")
    decompiler_version: str | None = Field(
        default=None,
        description="Version of the decompiler",
    )
    total_time_seconds: float = Field(
        default=0.0,
        description="Total time taken for decompilation",
    )
    timeout_occurred: bool = Field(
        default=False,
        description="Whether a timeout occurred during decompilation",
    )
    failed_functions: list[str] = Field(
        default_factory=list,
        description="Functions that failed to decompile",
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional decompiler-specific metadata",
    )


class DecompilationResult(BaseModel):
    """Complete decompilation result for a binary."""

    binary_path: Path = Field(..., description="Path to the source binary")
    binary_name: str = Field(..., description="Name of the binary")

    # Decompiler information
    decompiler: DecompilerMetadata = Field(
        ...,
        description="Metadata about the decompiler",
    )

    # Function-level results
    functions: dict[str, FunctionDecompilation] = Field(
        default_factory=dict,
        description="Decompilation results keyed by function name",
    )

    # Combined output
    combined_source: str | None = Field(
        default=None,
        description="All functions combined into a single C file",
    )

    # Output paths
    output_dir: Path | None = Field(
        default=None,
        description="Directory where output files are stored",
    )

    @property
    def function_count(self) -> int:
        return len(self.functions)

    @property
    def successful_count(self) -> int:
        return len(self.functions) - len(self.decompiler.failed_functions)

    def get_function(self, name: str) -> FunctionDecompilation | None:
        """Get decompilation for a specific function."""
        return self.functions.get(name)

    def to_c_file(self, path: Path) -> None:
        """Write combined decompilation to a C file."""
        with open(path, "w") as f:
            for func in self.functions.values():
                f.write(f"// Function: {func.name} @ 0x{func.address:x}\n")
                f.write(func.decompiled_code)
                f.write("\n\n")

    def to_toml(self, path: Path) -> None:
        """Save decompilation result metadata to TOML."""
        import toml

        data = {
            "binary": self.binary_name,
            "decompiler": self.decompiler.decompiler_name,
            "version": self.decompiler.decompiler_version,
            "total_time": self.decompiler.total_time_seconds,
            "timeout": self.decompiler.timeout_occurred,
            "function_count": self.function_count,
            "failed_functions": self.decompiler.failed_functions,
        }

        # Add per-function metadata. The structured cost fields ride along when
        # set (they round-trip through toml.load; scoring/cost.py's structured
        # scan reads them back), and are omitted when None so batch backends'
        # artifacts are byte-identical to before the fields existed.
        for name, func in self.functions.items():
            entry: dict[str, Any] = {
                "address": hex(func.address),
                "line_count": func.line_count,
                **func.metadata,
            }
            if func.time_seconds is not None:
                entry["time_seconds"] = func.time_seconds
            if func.llm_tokens is not None:
                entry["llm_tokens"] = dict(func.llm_tokens)
            data[f"functions.{name}"] = entry

        with open(path, "w") as f:
            toml.dump(data, f)

    @classmethod
    def from_toml(cls, path: Path) -> DecompilationResult:
        """Load decompilation result from TOML (metadata only)."""
        import toml

        data = toml.load(path)

        return cls(
            binary_path=Path(data.get("binary_path", "")),
            binary_name=data["binary"],
            decompiler=DecompilerMetadata(
                decompiler_name=data["decompiler"],
                decompiler_version=data.get("version"),
                total_time_seconds=data.get("total_time", 0.0),
                timeout_occurred=data.get("timeout", False),
                failed_functions=data.get("failed_functions", []),
            ),
        )
