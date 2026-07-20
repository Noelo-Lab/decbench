"""Recompilation byte-match metric.

Recompiles decompiled C code and compares the resulting assembly
against the original binary's assembly using disassembly-level diffing.

Based on the approach from Decomperson (USENIX Security 2022).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.metrics.base import Metric, MetricConfig
from decbench.metrics.registry import register_metric
from decbench.models.metrics import AggregationType, MetricResult, MetricValue

if TYPE_CHECKING:
    from networkx import DiGraph

    from decbench.models.decompilation import DecompilationResult, FunctionDecompilation

logger = logging.getLogger(__name__)


# Branch/call mnemonics whose operand is a code address. After single-function
# recompilation that target is an *unlinked* relative displacement (or a
# different absolute, since we disassemble the original at its real vaddr and the
# recompiled object at 0), so the printed target is layout/linker-dependent and
# must be normalized away before diffing — otherwise every call/jump counts as a
# mismatch even when the control flow is identical.
_BRANCH_MNEMONICS = frozenset(
    {
        "call",
        "jmp",
        "loop",
        "loope",
        "loopne",
        "jecxz",
        "jrcxz",
        "je",
        "jne",
        "jz",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "jnc",
        "js",
        "jns",
        "jo",
        "jno",
        "jp",
        "jnp",
        "jpe",
        "jpo",
        "jcxz",
        # ARM / AArch64 branches.
        "b",
        "bl",
        "blx",
        "bx",
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "cbz",
        "cbnz",
    }
)

# An immediate literal, optionally ARM-style ``#``-prefixed (and possibly
# negative), hex OR decimal: ``0x40``, ``#0x40``, ``#-0x40``, and the bare
# decimal form capstone prints for small displacements/targets (``call 4``).
_HEX_TOKEN = re.compile(r"#?-?(?:0x[0-9a-fA-F]+|\d+)")
# A PC/IP-relative *memory* operand: x86 ``[rip + 0x..]`` / ``[rip - 0x..]`` and
# AArch64 literal loads ``[pc, #0x..]``. The displacement encodes a data/GOT
# offset fixed up at link time, so it is layout-dependent and gets a placeholder.
# The displacement is OPTIONAL and may be decimal: in an *unlinked* object the
# relocation slot is 0 and capstone prints a bare ``[rip]`` (and small
# displacements print as decimal, e.g. ``[rip + 7]``) — without matching those,
# every global/string access in a recompiled object mismatches its linked
# original purely because of linking.
_PC_REL_MEM = re.compile(r"\[(rip|pc)(?:\s*[+\-,]\s*#?-?(?:0x[0-9a-fA-F]+|\d+))?\]")
# AArch64 PC-relative *address* computations whose immediate is the (page)
# target itself — capstone prints e.g. ``adrp x0, #0x400000``.
_PC_REL_MNEMONICS = frozenset({"adrp", "adr"})


def _normalize_operands(mnemonic: str, op_str: str) -> str:
    """Replace layout/linker-dependent operand values with a stable placeholder.

    Branch/call targets and PC-relative displacements differ between the
    original (linked, at its real vaddr) and the recompiled single-function
    object (unlinked, based at 0) even when the instruction is semantically the
    same. We blank those so the diff measures *real* assembly differences, not
    relocation noise — the central fairness fix for this metric.
    """
    # PC-relative data references: [rip + 0x..] / [pc, #0x..] -> [<base>+X]
    op_str = _PC_REL_MEM.sub(lambda m: f"[{m.group(1)}+X]", op_str)
    # Blank the immediate when it IS a link-dependent address: AArch64 adrp/adr
    # (the immediate is the PC-relative target), or a DIRECT branch/call target
    # (a bare address, no memory operand). An indirect ``call [rax + 0x20]``
    # displacement is a base-independent struct/vtable offset — a real difference
    # we keep — so memory-operand branches are excluded.
    if mnemonic in _PC_REL_MNEMONICS or (mnemonic in _BRANCH_MNEMONICS and "[" not in op_str):
        op_str = _HEX_TOKEN.sub("X", op_str)
    return op_str


def _disassemble_bytes(data: bytes, address: int = 0, arch_mode: tuple | None = None) -> list[str]:
    """Disassemble bytes to normalized assembly lines using capstone.

    ``arch_mode`` is a (capstone arch, capstone mode) tuple matching the
    binary's architecture (x86-32/64, ARM, ...). Defaults to x86-64.
    Skips nops (alignment padding) and normalizes layout/linker-dependent
    operands (branch targets, PC-relative displacements) for a fair comparison.
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

            op_str = _normalize_operands(insn.mnemonic, insn.op_str)
            line = f"{insn.mnemonic} {op_str}".strip()
            lines.append(line)

        # Drop x86-64 varargs AL-zeroing (``mov eax, 0`` / ``xor eax, eax``
        # immediately before a call): the SysV ABI makes callers zero AL for
        # variadic/unprototyped callees, so its presence tracks whether a
        # *prototype* was in scope at compile time — for recompiled decompiler
        # output the prototype is our injected scaffolding, not the
        # decompiler's logic. Applied to BOTH listings uniformly. ONLY on
        # x86-64: i386 (regparm) and Win64 have no AL-varargs convention, so a
        # ``xor eax, eax`` before a call there is a real register argument.
        if arch_mode == (capstone.CS_ARCH_X86, capstone.CS_MODE_64):
            lines = [
                ln
                for i, ln in enumerate(lines)
                if not (
                    ln in ("mov eax, 0", "xor eax, eax")
                    and i + 1 < len(lines)
                    and lines[i + 1].startswith("call ")
                )
            ]

        return lines

    except ImportError:
        logger.warning("capstone not available, falling back to raw byte comparison")
        return []


def _compute_jaccard_similarity(lines_a: list[str], lines_b: list[str]) -> tuple[float, int]:
    """Jaccard similarity AND absolute changed-line count between two asm listings.

    Returns ``(similarity, changed_lines)`` where similarity = ``shared / (a_only +
    shared + b_only)`` and ``changed_lines = a_only + b_only`` (the raw edit
    distance surfaced on the report's 'distance' view — number of assembly lines
    that differ). Uses a line-level diff (diff_match_patch style).
    """
    if not lines_a and not lines_b:
        return 1.0, 0
    if not lines_a or not lines_b:
        return 0.0, len(lines_a) + len(lines_b)

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
            return 1.0, 0
        return shared / total, a_only + b_only

    except ImportError:
        # Fall back to simple set-based Jaccard
        set_a = set(lines_a)
        set_b = set(lines_b)
        intersection = set_a & set_b
        union = set_a | set_b
        if not union:
            return 1.0, 0
        return len(intersection) / len(union), len(set_a ^ set_b)


def _compile_function(
    code: str,
    func_name: str,
    compiler: str = "gcc",
    flags: list[str] | None = None,
) -> Path | None:
    """Compile a single function's decompiled code to an object file.

    Thin wrapper over :func:`decbench.metrics.fixup.compile_with_fixup` (which
    maximizes the odds the code builds). Returns the object path or ``None``.
    """
    from decbench.metrics.fixup import compile_with_fixup

    result = compile_with_fixup(code, func_name, compiler, flags)
    return result.obj_path


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

    # v5: rip/pc-relative normalization also covers the unlinked-object bare
    # ``[rip]`` (zero/decimal displacement) form; direct branch/call targets
    # normalize decimal as well as hex; x86-64-only varargs AL-zeroing before
    # calls is dropped from both listings; fixup gains width-correct IDA/Ghidra
    # pseudo-types, semantically-correct helper macros, sibling/libc prototypes,
    # struct synthesis, positional repairs and a malformed-decl backout, and
    # producer_flags now carries codegen ``-f`` flags. (NOTE: a bare ``[rip]``
    # conflates reads of *different* globals — the same accepted precision limit
    # the linked-side hex displacement always had; symbol identity isn't
    # compared.)
    cache_version = "5"

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

        # Sibling prototypes (the decompiler's OWN recovered signatures for the
        # binary's other functions) shape the fixup's injected decls, so they
        # are part of the cache key.
        context_decls: dict[str, str] | None = kwargs.get("context_decls")
        key_inputs = [
            decompiled.decompiled_code,
            decompiled.name,
            decompiled.address,
            original_bytes.hex(),
            recompiler,
            list(flags),
            sorted(context_decls.items()) if context_decls else None,
        ]
        return self._cached_value(
            key_inputs,
            lambda: self._compute_uncached(
                decompiled, original_bytes, recompiler, flags, arch_mode, context_decls
            ),
        )

    def _compute_uncached(
        self,
        decompiled: FunctionDecompilation,
        original_bytes: bytes,
        compiler: str,
        flags: list[str],
        arch_mode: tuple | None,
        context_decls: dict[str, str] | None = None,
    ) -> MetricValue:
        import shutil

        from decbench.metrics.fixup import compile_with_fixup
        from decbench.utils import binfmt

        # Compile decompiled code the same way as source (matching toolchain),
        # running the fixup/self-repair pass so the maximum number of functions
        # build (otherwise non-compiling code is a flat 0 and dominates).
        fix = compile_with_fixup(
            decompiled.decompiled_code,
            decompiled.name,
            compiler,
            flags,
            context_decls=context_decls,
        )
        obj_path = fix.obj_path

        if obj_path is None:
            return MetricValue(
                value=0.0,
                metadata={
                    "compilable": False,
                    "fixup_iterations": fix.iterations,
                    "error": "Compilation failed",
                },
            )

        # The fixup pass places the object in its own temp dir; clean the dir.
        obj_dir = obj_path.parent
        fixup_meta = {
            "compilable": True,
            "fixup_iterations": fix.iterations,
            "fixup_injected": len(fix.injected),
        }
        try:
            # Extract recompiled function bytes (.text of the single-function
            # object — ELF or COFF/MinGW).
            recompiled_bytes = binfmt.object_text_bytes(obj_path, decompiled.name)

            if recompiled_bytes is None:
                return MetricValue(
                    value=0.0,
                    metadata={**fixup_meta, "error": "Could not extract recompiled bytes"},
                )

            # First check exact byte match
            if recompiled_bytes == original_bytes:
                return MetricValue(
                    value=1.0,
                    raw_value=True,
                    metadata={
                        **fixup_meta,
                        "exact_match": True,
                        "changed_lines": 0,
                        "original_size": len(original_bytes),
                        "recompiled_size": len(recompiled_bytes),
                    },
                )

            # Disassemble (with the binary's own arch) and compute similarity
            original_asm = _disassemble_bytes(original_bytes, decompiled.address, arch_mode)
            recompiled_asm = _disassemble_bytes(recompiled_bytes, 0, arch_mode)

            if original_asm and recompiled_asm:
                similarity, changed_lines = _compute_jaccard_similarity(
                    original_asm, recompiled_asm
                )
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
                changed_lines = abs(len(original_bytes) - len(recompiled_bytes))

            # A perfect match requires similarity == 1.0
            return MetricValue(
                value=1.0 if similarity == 1.0 else similarity,
                raw_value=similarity,
                metadata={
                    **fixup_meta,
                    "exact_match": False,
                    "jaccard_similarity": similarity,
                    # Absolute edit distance (# changed asm lines) for the report's
                    # 'distance' view; does not affect the (unchanged) jaccard score.
                    "changed_lines": changed_lines,
                    "original_size": len(original_bytes),
                    "recompiled_size": len(recompiled_bytes),
                    "original_asm_lines": len(original_asm),
                    "recompiled_asm_lines": len(recompiled_asm),
                },
            )

        finally:
            shutil.rmtree(obj_dir, ignore_errors=True)

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

        # ABSTAIN (emit no per-function results) when the matching recompile
        # toolchain isn't installed for this binary's format/arch — e.g. ARM
        # firmware (cps) or PE malware decompiled on an x86 host without the
        # cross/mingw gcc. Scoring those 0 would be unfair ("couldn't measure" is
        # not "wrong"); abstaining drops byte_match for the binary so GED +
        # type_match carry it (per-metric denominators already differ).
        if original_binary_path is not None:
            from decbench.utils import binfmt

            info = binfmt.detect(original_binary_path)
            if info is not None:
                recompiler = binfmt.recompiler_for(info)
                if recompiler is None or not binfmt.tool_available(recompiler):
                    return MetricResult(
                        metric_name=self.name,
                        decompiler_name=decompilation.decompiler.decompiler_name,
                        binary_name=decompilation.binary_name,
                        function_results={},
                        computation_time_seconds=time.time() - start_time,
                        errors=[
                            f"abstained: no recompile toolchain ({recompiler}) "
                            f"for {info.fmt}/{info.arch}"
                        ],
                    )

        # The decompiler's own signatures for this binary's functions: used by
        # the fixup to give internal calls real prototypes.
        from decbench.metrics.fixup import derive_context_decls

        context_decls = derive_context_decls(
            {name: fd.decompiled_code or "" for name, fd in decompilation.functions.items()}
        )

        for func_name, func_decomp in decompilation.functions.items():
            try:
                value = self.compute_for_function(
                    func_decomp,
                    original_binary_path=original_binary_path,
                    context_decls=context_decls,
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
