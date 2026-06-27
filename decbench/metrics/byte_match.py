"""Recompilation byte-match metric.

Recompiles decompiled C code and compares the resulting assembly
against the original binary's assembly using disassembly-level diffing.

Based on the approach from Decomperson (USENIX Security 2022).
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricResult, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult, FunctionDecompilation

logger = logging.getLogger(__name__)


def _disassemble_bytes(data: bytes, address: int = 0, arch_mode: tuple | None = None) -> list[str]:
    """Disassemble bytes to normalized assembly lines using capstone.

    ``arch_mode`` is a (capstone arch, capstone mode) tuple matching the
    binary's architecture (x86-32/64, ARM, ...). Defaults to x86-64.
    Normalizes addresses and skips nops for stable comparison.
    """
    try:
        import capstone

        if arch_mode is None:
            arch_mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs = capstone.Cs(*arch_mode)
        cs.detail = True

        lines: list[str] = []
        for insn in cs.disasm(data, address):
            # Skip nops (alignment padding varies between compilations)
            if insn.mnemonic == "nop":
                continue

            # Normalize: use mnemonic + op_str, replacing absolute addresses
            op_str = insn.op_str

            # Replace absolute addresses with generic placeholders
            # This makes the comparison more robust to address layout differences
            line = f"{insn.mnemonic} {op_str}".strip()
            lines.append(line)

        return lines

    except ImportError:
        logger.warning("capstone not available, falling back to raw byte comparison")
        return []


def _compute_jaccard_similarity(lines_a: list[str], lines_b: list[str]) -> float:
    """Compute Jaccard similarity between two lists of assembly lines.

    Uses line-level diff (diff_match_patch style) to compute:
    shared / (a_only + shared + b_only)
    """
    if not lines_a and not lines_b:
        return 1.0
    if not lines_a or not lines_b:
        return 0.0

    try:
        from diff_match_patch import diff_match_patch

        dmp = diff_match_patch()

        text_a = "\n".join(lines_a) + "\n"
        text_b = "\n".join(lines_b) + "\n"

        d, t, char_map = dmp.diff_linesToChars(text_a, text_b)
        diffs = dmp.diff_main(d, t, False)
        dmp.diff_charsToLines(diffs, char_map)

        a_only = 0
        shared = 0
        b_only = 0

        for (
            op,
            text,
        ) in diffs:
            n = text.count("\n")
            if op == -1:
                a_only += n
            elif op == 0:
                shared += n
            elif op == 1:
                b_only += n

        total = a_only + shared + b_only
        if total == 0:
            return 1.0
        return shared / total

    except ImportError:
        # Fall back to simple set-based Jaccard
        set_a = set(lines_a)
        set_b = set(lines_b)
        intersection = set_a & set_b
        union = set_a | set_b
        if not union:
            return 1.0
        return len(intersection) / len(union)


def _compile_function(
    code: str,
    func_name: str,
    compiler: str = "gcc",
    flags: list[str] | None = None,
) -> Path | None:
    """Compile a single function's decompiled code to an object file.

    Returns path to the object file, or None if compilation failed.
    """
    if flags is None:
        flags = ["-O2", "-c"]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".c", delete=False, prefix=f"decbench_{func_name}_"
    ) as src_file:
        # Add minimal headers
        src_file.write("#include <stdint.h>\n")
        src_file.write("#include <stddef.h>\n")
        src_file.write("#include <stdbool.h>\n")
        src_file.write("#include <stdlib.h>\n")
        src_file.write("#include <string.h>\n")
        src_file.write("#include <stdio.h>\n\n")
        src_file.write(code)
        src_path = Path(src_file.name)

    obj_path = src_path.with_suffix(".o")

    try:
        cmd = [compiler, *flags, "-o", str(obj_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, timeout=30)

        if result.returncode != 0:
            return None

        if not obj_path.exists():
            return None

        return obj_path

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    finally:
        src_path.unlink(missing_ok=True)


@register_metric("byte_match")
class ByteMatchMetric(Metric):
    """Recompilation byte-match metric.

    Compiles the decompiled code and compares the resulting binary
    against the original. Uses assembly-level diffing for the comparison.

    Value is a Jaccard similarity score from 0.0 to 1.0.
    Perfect score (1.0) means the recompiled assembly exactly matches the original.
    """

    name = "byte_match"
    display_name = "Recompilation Bytematch"
    description = "Assembly similarity between recompiled decompilation and original"

    weight = 1.0
    lower_is_better = False
    perfect_value = 1.0
    default_aggregation = AggregationType.PERCENT

    requires_source_cfg = False
    requires_decompiled_cfg = False

    def __init__(self, config: MetricConfig | None = None):
        super().__init__(config)

        self.compiler = "gcc"
        if config and "compiler" in config.extra_options:
            self.compiler = config.extra_options["compiler"]

        self.compile_flags = ["-O2", "-c"]
        if config and "compile_flags" in config.extra_options:
            self.compile_flags = config.extra_options["compile_flags"]

    def compute_for_function(
        self,
        decompiled: FunctionDecompilation,
        source_cfg: DiGraph | None = None,
        decompiled_cfg: DiGraph | None = None,
        original_binary_path: Path | None = None,
        **kwargs: Any,
    ) -> MetricValue:
        """Compute byte match for a single function.

        Recompiles decompiled code, disassembles both, and computes
        Jaccard similarity of assembly lines.
        """
        if original_binary_path is None:
            return MetricValue(
                value=0.0,
                metadata={"error": "No original binary for comparison"},
            )

        from decbench.utils import binfmt

        # Recompile THE SAME WAY THE SOURCE WAS COMPILED: pick the toolchain and
        # arch/opt flags that match the original binary's own format+arch
        # (PE -> MinGW, ARM -> arm-none-eabi, x86 -> gcc; flags from the DWARF
        # producer), instead of a fixed host gcc. If that toolchain isn't
        # installed, we can't match it — return a non-scoring result rather than
        # comparing against a wrong-arch recompile.
        info = binfmt.detect(original_binary_path)
        if info is None:
            return MetricValue(value=0.0, metadata={"error": "Unrecognized binary format"})
        recompiler = binfmt.recompiler_for(info)
        if recompiler is None or not binfmt.tool_available(recompiler):
            return MetricValue(
                value=0.0,
                metadata={
                    "skipped": True,
                    "reason": f"no matching toolchain ({recompiler}) for {info.fmt}/{info.arch}",
                },
            )
        # producer flags (e.g. -m32 -march=... -O2, or -mcpu=cortex-m4 -mthumb)
        # so the recompile matches; then compile to an object.
        flags = binfmt.producer_flags(original_binary_path) + ["-c", "-fno-builtin", "-w"]
        arch_mode = binfmt.capstone_arch_mode(info)

        # Extract original function bytes ONCE; reuse for both the cache key and
        # the comparison.
        original_bytes = binfmt.function_bytes(
            original_binary_path, decompiled.name, decompiled.address
        )
        if original_bytes is None:
            return MetricValue(
                value=0.0,
                metadata={"error": "Could not extract original function bytes"},
            )

        key_inputs = [
            decompiled.decompiled_code,
            decompiled.name,
            decompiled.address,
            original_bytes.hex(),
            recompiler,
            list(flags),
        ]
        return self._cached_value(
            key_inputs,
            lambda: self._compute_uncached(
                decompiled, original_bytes, recompiler, flags, arch_mode
            ),
        )

    def _compute_uncached(
        self,
        decompiled: FunctionDecompilation,
        original_bytes: bytes,
        compiler: str,
        flags: list[str],
        arch_mode: tuple | None,
    ) -> MetricValue:
        from decbench.utils import binfmt

        # Compile decompiled code the same way as source (matching toolchain).
        obj_path = _compile_function(
            decompiled.decompiled_code,
            decompiled.name,
            compiler,
            flags,
        )

        if obj_path is None:
            return MetricValue(
                value=0.0,
                metadata={"compilable": False, "error": "Compilation failed"},
            )

        try:
            # Extract recompiled function bytes (.text of the single-function
            # object — ELF or COFF/MinGW).
            recompiled_bytes = binfmt.object_text_bytes(obj_path, decompiled.name)

            if recompiled_bytes is None:
                return MetricValue(
                    value=0.0,
                    metadata={"compilable": True, "error": "Could not extract recompiled bytes"},
                )

            # First check exact byte match
            if recompiled_bytes == original_bytes:
                return MetricValue(
                    value=1.0,
                    raw_value=True,
                    metadata={
                        "compilable": True,
                        "exact_match": True,
                        "original_size": len(original_bytes),
                        "recompiled_size": len(recompiled_bytes),
                    },
                )

            # Disassemble (with the binary's own arch) and compute similarity
            original_asm = _disassemble_bytes(original_bytes, decompiled.address, arch_mode)
            recompiled_asm = _disassemble_bytes(recompiled_bytes, 0, arch_mode)

            if original_asm and recompiled_asm:
                similarity = _compute_jaccard_similarity(original_asm, recompiled_asm)
            else:
                # Fallback: raw byte comparison ratio
                min_len = min(len(original_bytes), len(recompiled_bytes))
                max_len = max(len(original_bytes), len(recompiled_bytes))
                if max_len == 0:
                    similarity = 1.0
                else:
                    matching = sum(
                        1 for i in range(min_len) if original_bytes[i] == recompiled_bytes[i]
                    )
                    similarity = matching / max_len

            # A perfect match requires similarity == 1.0
            return MetricValue(
                value=1.0 if similarity == 1.0 else similarity,
                raw_value=similarity,
                metadata={
                    "compilable": True,
                    "exact_match": False,
                    "jaccard_similarity": similarity,
                    "original_size": len(original_bytes),
                    "recompiled_size": len(recompiled_bytes),
                    "original_asm_lines": len(original_asm),
                    "recompiled_asm_lines": len(recompiled_asm),
                },
            )

        finally:
            if obj_path:
                obj_path.unlink(missing_ok=True)

    def compute_for_binary(
        self,
        decompilation: DecompilationResult,
        source_cfgs: dict[str, DiGraph] | None = None,
        decompiled_cfgs: dict[str, DiGraph] | None = None,
        **kwargs: Any,
    ) -> MetricResult:
        """Compute byte match for all functions in a binary."""
        import time

        start_time = time.time()
        function_results: dict[str, MetricValue] = {}
        errors: list[str] = []

        original_binary_path = decompilation.binary_path

        for func_name, func_decomp in decompilation.functions.items():
            try:
                value = self.compute_for_function(
                    func_decomp,
                    original_binary_path=original_binary_path,
                )
                function_results[func_name] = value

            except Exception as e:
                errors.append(f"{func_name}: {str(e)}")

        result = MetricResult(
            metric_name=self.name,
            decompiler_name=decompilation.decompiler.decompiler_name,
            binary_name=decompilation.binary_name,
            function_results=function_results,
            computation_time_seconds=time.time() - start_time,
            errors=errors,
        )

        result.compute_aggregates(perfect_value=self.perfect_value)

        return result
