"""Byte-match correctness metric."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricCategory, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import FunctionDecompilation


@register_metric("byte_match")
class ByteMatchMetric(Metric):
    """Byte-match correctness metric.

    Compiles the decompiled code and compares the resulting binary
    with the original. A match indicates semantic equivalence.

    This is a challenging metric that requires:
    1. The decompiled code to be compilable
    2. The compiled result to match the original binary

    Value is 1.0 for match, 0.0 for no match.
    """

    name = "byte_match"
    display_name = "Byte Match"
    description = "Whether recompiled decompilation matches original binary"
    category = MetricCategory.CORRECT

    weight = 1.0
    lower_is_better = False  # Higher is better (1.0 = match)
    perfect_value = 1.0
    default_aggregation = AggregationType.PERCENT

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)

        # Get compiler from config
        self.compiler = "gcc"
        if config and "compiler" in config.extra_options:
            self.compiler = config.extra_options["compiler"]

        # Get compiler flags
        self.compile_flags = ["-O2", "-c"]
        if config and "compile_flags" in config.extra_options:
            self.compile_flags = config.extra_options["compile_flags"]

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        original_binary_path: Path | None = None,
        original_function_bytes: bytes | None = None,
        **kwargs,
    ) -> MetricValue:
        """Check if decompiled code produces matching binary.

        Args:
            decompiled: The decompiled function
            original_binary_path: Path to original binary (for extraction)
            original_function_bytes: Pre-extracted original function bytes

        Returns:
            MetricValue with 1.0 for match, 0.0 for no match
        """
        # Need original bytes for comparison
        if original_function_bytes is None and original_binary_path is None:
            return MetricValue(
                value=0.0,
                metadata={"error": "No original binary for comparison"},
            )

        # Try to compile the decompiled code
        try:
            compiled_bytes = self._compile_function(decompiled)
        except Exception as e:
            return MetricValue(
                value=0.0,
                metadata={
                    "compilable": False,
                    "error": str(e),
                },
            )

        if compiled_bytes is None:
            return MetricValue(
                value=0.0,
                metadata={"compilable": False},
            )

        # Get original bytes if not provided
        if original_function_bytes is None:
            original_function_bytes = self._extract_function_bytes(
                original_binary_path,
                decompiled.address,
            )

        if original_function_bytes is None:
            return MetricValue(
                value=0.0,
                metadata={"error": "Could not extract original bytes"},
            )

        # Compare bytes
        matches = compiled_bytes == original_function_bytes

        return MetricValue(
            value=1.0 if matches else 0.0,
            raw_value=matches,
            metadata={
                "compilable": True,
                "original_size": len(original_function_bytes),
                "compiled_size": len(compiled_bytes),
                "size_match": len(original_function_bytes) == len(compiled_bytes),
            },
        )

    def _compile_function(
        self, decompiled: FunctionDecompilation
    ) -> bytes | None:
        """Compile decompiled code and extract function bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write source file
            src_file = tmpdir / f"{decompiled.name}.c"
            with open(src_file, "w") as f:
                # Add minimal headers
                f.write("#include <stdint.h>\n")
                f.write("#include <stddef.h>\n\n")
                f.write(decompiled.decompiled_code)

            # Compile
            obj_file = tmpdir / f"{decompiled.name}.o"
            cmd = [
                self.compiler,
                *self.compile_flags,
                "-o", str(obj_file),
                str(src_file),
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return None

            if not obj_file.exists():
                return None

            # Extract function bytes from object file
            return self._extract_function_from_object(obj_file, decompiled.name)

    def _extract_function_from_object(
        self,
        obj_path: Path,
        func_name: str,
    ) -> bytes | None:
        """Extract function bytes from an object file."""
        try:
            from elftools.elf.elffile import ELFFile

            with open(obj_path, "rb") as f:
                elf = ELFFile(f)

                # Find .text section
                text_section = elf.get_section_by_name(".text")
                if text_section is None:
                    return None

                # Find symbol
                symtab = elf.get_section_by_name(".symtab")
                if symtab is None:
                    return None

                for sym in symtab.iter_symbols():
                    if sym.name == func_name:
                        offset = sym["st_value"]
                        size = sym["st_size"]

                        if size == 0:
                            return None

                        # Extract bytes
                        data = text_section.data()
                        return data[offset : offset + size]

        except Exception:
            pass

        return None

    def _extract_function_bytes(
        self,
        binary_path: Path,
        address: int,
    ) -> bytes | None:
        """Extract function bytes from original binary."""
        try:
            from elftools.elf.elffile import ELFFile

            with open(binary_path, "rb") as f:
                elf = ELFFile(f)

                # Find symbol at address
                symtab = elf.get_section_by_name(".symtab")
                if symtab is None:
                    return None

                for sym in symtab.iter_symbols():
                    if sym["st_value"] == address:
                        size = sym["st_size"]
                        if size == 0:
                            continue

                        # Find containing section
                        for section in elf.iter_sections():
                            if (
                                section["sh_addr"] <= address
                                and address <
                                section["sh_addr"] + section["sh_size"]
                            ):
                                offset = address - section["sh_addr"]
                                data = section.data()
                                return data[offset : offset + size]

        except Exception:
            pass

        return None
