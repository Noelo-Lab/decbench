"""Raw Binary Ninja decompiler backend (no declib), via the headless API.

Drives Binary Ninja's headless API directly:

* ``binaryninja.load(path)`` (or ``BinaryViewType.get_view_of_file``) to open +
  analyze the binary,
* iterate ``bv.functions``,
* C pseudocode from the High Level IL (``func.hlil``), rendered with the C
  language representation, and
* variables from ``func.vars`` / ``func.parameter_vars`` (args carry an index;
  stack vars carry a frame-relative storage offset).

Binary Ninja is **not installed on this machine** (no ``binaryninja`` module
and no license), so this backend is written to be correct but
``is_available()`` reports ``False`` here. The module never imports binaryninja
at import time, and any license/import failure is treated as unavailable.
"""

from __future__ import annotations

import contextlib
import logging
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)

_l = logging.getLogger(__name__)


@register_decompiler("binja")
class RawBinjaDecompiler(Decompiler):
    """Binary Ninja driven natively via the headless API, without declib."""

    name = "binja"
    display_name = "Binary Ninja"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        """Whether a licensed, importable Binary Ninja is present.

        License errors raise non-``ImportError`` exceptions, so any failure is
        treated as unavailable.
        """
        try:
            import binaryninja  # noqa: F401

            return True
        except Exception:  # noqa: BLE001
            return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            import binaryninja

            return str(binaryninja.core_version())
        except Exception:  # noqa: BLE001
            return "unknown"

    def _load(self, binary_path: Path) -> Any:
        """Open + analyze a binary, returning a BinaryView.

        CRITICAL: always ``update_analysis_and_wait()`` before rendering. Even
        though ``binaryninja.load()`` kicks off analysis, it can return before
        per-function HLIL / the linear language-representation view is ready, so
        the Pseudo-C render emits the literal ``Loading...`` placeholder instead
        of code (previously ~73% of binja function bodies on large binaries —
        the dominant cause of binja's near-zero GED/byte scores). Waiting here
        forces analysis to completion first.
        """
        import binaryninja

        # ``load`` runs analysis and is the modern entry point; fall back to the
        # older BinaryViewType API if ``load`` is unavailable.
        if hasattr(binaryninja, "load"):
            bv = binaryninja.load(str(binary_path))
        else:
            bv = binaryninja.BinaryViewType.get_view_of_file(str(binary_path))
        if bv is not None:
            with contextlib.suppress(Exception):
                bv.update_analysis_and_wait()
        return bv

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        if not self.is_available():
            return []
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)
        bv = None
        try:
            bv = self._load(binary_path)
            return self._enumerate(bv, elf_base, text_range)
        except Exception as e:  # noqa: BLE001
            _l.error("binja-raw: failed to discover functions in %s: %s", binary_path, e)
            return []
        finally:
            if bv is not None:
                with contextlib.suppress(Exception):
                    bv.file.close()

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []
        # Count of DWARF targets we force-created because auto-analysis missed
        # them (surfaced in metadata). Read as a closure free variable by _meta.
        forced_functions = 0

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "binja", "via": "raw"}
            if partial:
                extra["partial"] = True
            if forced_functions:
                extra["forced_functions"] = forced_functions
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start_time,
                failed_functions=list(failed_functions),
                extra=extra,
            )

        def _dump() -> None:
            if progress_path is None:
                return
            partial = DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=_meta(partial=True),
                functions=dict(decompiled_functions),
                output_dir=output_dir,
            )
            common.dump_progress(progress_path, partial)

        bv = None
        try:
            bv = self._load(binary_path)
            enumerated = self._enumerate(bv, elf_base, text_range)
            if functions is not None:
                requested = {n for (n, _a) in functions}
                enumerated = [(n, a) for (n, a) in enumerated if n in requested]
            enumerated = common.narrow_to_source(
                enumerated,
                function_names,
                backend="binja",
                binary_name=binary_path.name,
            )
            load_base = self._binja_load_base(bv)
            by_addr = {int(f.start): f for f in bv.functions}

            # Force-create DWARF targets binja's auto-analysis missed. On
            # stripped Cortex-M firmware these are vector/pointer-table functions
            # binja never auto-promotes; force-creating them isolates
            # decompilation quality from boundary discovery (every backend gets
            # the same DWARF target list). Only reached on the normal path.
            covered = {(int(f.start) - load_base) + elf_base for f in bv.functions}
            missing = common.missing_targets(covered, function_names, text_range)
            if missing:
                plat = self._force_platform(bv)
                for file_addr in missing:
                    binja_addr = (file_addr - elf_base) + load_base
                    try:
                        if plat is not None:
                            bv.add_function(binja_addr, plat)
                        else:
                            bv.add_function(binja_addr)
                    except Exception as e:  # noqa: BLE001
                        _l.debug("binja-raw: add_function at %#x failed: %s", file_addr, e)
                with contextlib.suppress(Exception):
                    bv.update_analysis_and_wait()
                by_addr = {int(f.start): f for f in bv.functions}
                for file_addr in missing:
                    binja_addr = (file_addr - elf_base) + load_base
                    func = by_addr.get(binja_addr)
                    if func is None:
                        continue
                    name = str(getattr(func, "name", "") or "") or f"sub_{binja_addr:x}"
                    enumerated.append((name, file_addr))
                    forced_functions += 1

            for func_name, file_addr in enumerated:
                func_result = None
                binja_addr = (file_addr - elf_base) + load_base
                func = by_addr.get(binja_addr)
                if func is not None:
                    try:
                        func_result = self._decompile_one(func, func_name, file_addr)
                    except Exception as e:  # noqa: BLE001
                        _l.debug("binja-raw: failed to decompile %s: %s", func_name, e)
                if func_result is not None:
                    decompiled_functions[func_name] = func_result
                else:
                    failed_functions.append(func_name)
                _dump()

        except Exception as e:  # noqa: BLE001
            _l.error("binja-raw failed on %s: %s", binary_path, e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra={"error": str(e), "backend": "binja", "via": "raw"},
                ),
            )
        finally:
            if bv is not None:
                with contextlib.suppress(Exception):
                    bv.file.close()

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=_meta(partial=False),
            functions=decompiled_functions,
            output_dir=output_dir,
        )

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    #
    # Binary Ninja helpers
    #

    @staticmethod
    def _binja_load_base(bv: Any) -> int:
        """The address binja loaded the binary at (its start/origin)."""
        try:
            return int(bv.start)
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _force_platform(bv: Any) -> Any:
        """Platform to force-create functions with, or ``None`` for binja's own.

        Cortex-M firmware is entirely Thumb, but binja can load such an ELF as
        plain ``armv7`` (ARM mode), in which case ``add_function`` would decode
        the Thumb bytes as ARM garbage that scores ~0. For any ARM-family view we
        therefore pin the ``thumb2`` platform. Non-ARM binaries use binja's
        default platform (return ``None``).
        """
        try:
            import binaryninja as bn

            arch_name = str(getattr(bv.arch, "name", "") or "").lower()
            if "thumb" in arch_name or "arm" in arch_name:
                with contextlib.suppress(Exception):
                    return bn.Platform["thumb2"]
                return getattr(bv, "platform", None)
        except Exception:  # noqa: BLE001
            pass
        return None

    def _enumerate(
        self,
        bv: Any,
        elf_base: int,
        text_range: tuple[int, int] | None,
    ) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-space addr) for benchmarkable functions."""
        load_base = self._binja_load_base(bv)
        out: list[tuple[str, int]] = []
        for func in bv.functions:
            try:
                # Skip thunks / trampolines when binja flags them.
                if getattr(func, "is_thunk", False):
                    continue
                name = str(func.name or "")
                file_addr = (int(func.start) - load_base) + elf_base
            except Exception:  # noqa: BLE001
                continue
            if common.should_skip_function(name, file_addr, text_range):
                continue
            out.append((name, file_addr))
        return sorted(out, key=lambda x: x[1])

    def _decompile_one(
        self,
        func: Any,
        func_name: str,
        file_addr: int,
    ) -> FunctionDecompilation | None:
        """Decompile one binja function via HLIL -> FunctionDecompilation."""
        code = self._render_c(func)
        if not code:
            return None
        variables = self._extract_variables(func)
        line_mappings = self._extract_line_mappings(func, file_addr)
        metadata = common.extract_metrics(code)

        return FunctionDecompilation(
            name=func_name,
            address=file_addr,
            decompiled_code=code,
            line_count=code.count("\n") + 1,
            line_mappings=line_mappings,
            variables=variables,
            metadata=metadata,
        )

    @staticmethod
    def _render_c(func: Any) -> str:
        """Render a function as Binary Ninja **pseudo-C** text.

        Uses the linear-view *language representation* (the "Pseudo C" view),
        which emits real C-like source — proper signature, braces, ``int32_t``,
        ``return f(...)`` — so it parses (GED) and compiles (byte_match) like the
        other decompilers. The raw HLIL form (``func.hlil.lines``: ``rax = ...``,
        ``u>``, no braces) does NOT, which previously made GED/byte_match score
        binja near-zero. Falls back to HLIL only if the linear view is
        unavailable.
        """
        try:
            import binaryninja as bn

            def _walk() -> str:
                settings = bn.DisassemblySettings()
                lvo = bn.LinearViewObject.single_function_language_representation(func, settings)
                cursor = bn.LinearViewCursor(lvo)
                cursor.seek_to_begin()
                lines: list[str] = []
                # Bound the walk so a pathological function can't spin forever.
                for _ in range(100000):
                    for ln in cursor.lines:
                        lines.append(str(ln))
                    if not cursor.next():
                        break
                return "\n".join(lines).strip("\n")

            # Force HLIL (and thus pseudo-C) generation for THIS function before
            # rendering. Even after full binary analysis, binja 3.1's linear-view
            # language representation returns the literal 'Loading...' placeholder
            # until the function's HLIL is generated (it's lazy per-function).
            # Touching func.hlil forces that computation so the render yields real
            # C — without this, ~all functions in large binaries (e.g. bash: 2486
            # of 2499) render as Loading and get dropped.
            with contextlib.suppress(Exception):
                _ = func.hlil
                _ = len(list(func.hlil.instructions))

            text = _walk()
            # If the body is STILL the 'Loading...' placeholder (not C), force
            # this function's analysis and re-render once; a still-placeholder
            # body is treated as a FAILURE (return "") rather than emitting junk
            # that pollutes GED/byte_match.
            if not text.strip() or "Loading..." in text:
                with contextlib.suppress(Exception):
                    func.view.update_analysis_and_wait()
                text = _walk()
            if text.strip() and "Loading..." not in text:
                return text
        except Exception:  # noqa: BLE001
            pass

        # Fallback: stringify HLIL directly (not valid C, but better than empty).
        try:
            return "\n".join(str(line) for line in func.hlil.lines)
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _extract_variables(func: Any) -> list[VariableInfo]:
        """Pull arguments (ABI order) and stack vars from binja's Variables.

        ``func.parameter_vars`` lists arguments in ABI order; ``func.vars`` lists
        all variables. A binja ``Variable`` has ``name``, ``type`` (with
        ``.width``), and a ``storage`` that is a frame offset for stack vars
        (``source_type == VariableSourceType.StackVariableSourceType``).
        """
        variables: list[VariableInfo] = []
        param_set: set[Any] = set()
        try:
            params = list(func.parameter_vars)
        except Exception:  # noqa: BLE001
            params = []

        for idx, var in enumerate(params):
            param_set.add(var)
            variables.append(
                VariableInfo(
                    name=str(getattr(var, "name", "") or ""),
                    type=RawBinjaDecompiler._type_str(var),
                    stack_offset=None,
                    size=RawBinjaDecompiler._var_size(var),
                    kind="arg",
                    arg_index=idx,
                )
            )

        try:
            all_vars = list(func.vars)
        except Exception:  # noqa: BLE001
            all_vars = []

        for var in all_vars:
            if var in param_set:
                continue
            stack_offset = RawBinjaDecompiler._stack_offset(var)
            variables.append(
                VariableInfo(
                    name=str(getattr(var, "name", "") or ""),
                    type=RawBinjaDecompiler._type_str(var),
                    stack_offset=stack_offset,
                    size=RawBinjaDecompiler._var_size(var),
                    kind="stack",
                )
            )
        return variables

    @staticmethod
    def _type_str(var: Any) -> str:
        try:
            t = getattr(var, "type", None)
            return str(t) if t is not None else ""
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _var_size(var: Any) -> int | None:
        try:
            t = getattr(var, "type", None)
            if t is not None and getattr(t, "width", None):
                return int(t.width)
        except Exception:  # noqa: BLE001
            pass
        return None

    @staticmethod
    def _stack_offset(var: Any) -> int | None:
        """Frame-relative offset for a stack variable, else ``None``."""
        try:
            from binaryninja.enums import VariableSourceType

            if var.source_type == VariableSourceType.StackVariableSourceType:
                return int(var.storage)
        except Exception:  # noqa: BLE001
            pass
        return None

    @staticmethod
    def _extract_line_mappings(func: Any, file_addr: int) -> list[LineMapping]:
        """Best-effort line mappings from HLIL instruction addresses.

        Each HLIL line carries the originating instruction ``address``; binja
        loads non-relocatable ELFs at their link address so the address already
        equals ELF-file space. Returns ``[]`` if the API shape differs.
        """
        line_to_addrs: dict[int, set[int]] = {}
        try:
            hlil = func.hlil
            for line_no, instr in enumerate(hlil.instructions, start=1):
                addr = getattr(instr, "address", None)
                if addr is not None:
                    line_to_addrs.setdefault(line_no, set()).add(int(addr))
        except Exception:  # noqa: BLE001
            return []
        return common.merge_line_addresses(line_to_addrs)
