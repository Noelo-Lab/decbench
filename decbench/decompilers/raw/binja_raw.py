"""Raw Binary Ninja decompiler backend (no declib), via the headless API.

Drives Binary Ninja's headless API directly:

* ``binaryninja.load(path)`` (or ``BinaryViewType.get_view_of_file``) to open +
  analyze the binary,
* iterate ``bv.functions``,
* C pseudocode from the High Level IL (``func.hlil``), rendered with the C
  language representation, and
* variables from ``func.vars`` / ``func.parameter_vars`` (args carry an index;
  stack vars carry a frame-relative storage offset).

The module never imports binaryninja at import time, and any license/import
failure is treated as unavailable.
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

        if hasattr(binaryninja, "load"):
            bv = binaryninja.load(str(binary_path))
        else:
            bv = binaryninja.BinaryViewType.get_view_of_file(str(binary_path))
        if bv is not None:
            with contextlib.suppress(Exception):
                bv.update_analysis_and_wait()
        return bv

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

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "binja", "via": "raw"}
            if partial:
                extra["partial"] = True
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

    @staticmethod
    def _binja_load_base(bv: Any) -> int:
        """The address binja loaded the binary at (its start/origin)."""
        try:
            return int(bv.start)
        except Exception:  # noqa: BLE001
            return 0

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
        variables, variable_indices = self._extract_variables_with_identifiers(func)
        code, line_mappings, variable_lines = self._render_c_with_evidence(
            func,
            file_addr,
            variable_indices,
        )
        if not code:
            return None
        line_addresses = {mapping.line_number: set(mapping.addresses) for mapping in line_mappings}
        for index, lines in variable_lines.items():
            variables[index].line_numbers = sorted(lines)
            variables[index].addresses = sorted(
                {address for line in lines for address in line_addresses.get(line, set())}
            )
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
        """Compatibility wrapper around the canonical render/evidence pass."""
        code, _line_mappings, _variable_lines = RawBinjaDecompiler._render_c_with_evidence(
            func,
            int(getattr(func, "start", 0)),
            {},
        )
        return code

    @staticmethod
    def _render_c_with_evidence(
        func: Any,
        file_addr: int,
        variable_indices: dict[int, int],
    ) -> tuple[str, list[LineMapping], dict[int, set[int]]]:
        """Render a function as Binary Ninja **pseudo-C** text.

        Uses the linear-view *language representation* (the "Pseudo C" view),
        which emits real C-like source — proper signature, braces, ``int32_t``,
        ``return f(...)`` — so it parses (GED) and compiles (byte_match) like the
        other decompilers. The raw HLIL form (``func.hlil.lines``: ``rax = ...``,
        ``u>``, no braces) does NOT, which previously made GED/byte_match score
        binja near-zero. Falls back to HLIL only if the linear view is
        unavailable. Text and provenance are collected from the same cursor
        traversal so their 1-based line numbers cannot drift apart.
        """
        try:
            import binaryninja as bn
            from binaryninja.enums import InstructionTextTokenType, LinearDisassemblyLineType

            skipped_types = {
                LinearDisassemblyLineType.FunctionHeaderStartLineType,
                LinearDisassemblyLineType.FunctionHeaderEndLineType,
                LinearDisassemblyLineType.FunctionEndLineType,
                LinearDisassemblyLineType.AnalysisWarningLineType,
            }
            variable_types = {
                InstructionTextTokenType.LocalVariableToken,
                InstructionTextTokenType.StackVariableToken,
            }

            try:
                ranges = [(int(r.start), int(r.end)) for r in func.address_ranges]
            except Exception:  # noqa: BLE001
                try:
                    ranges = [(int(func.lowest_address), int(func.highest_address) + 1)]
                except Exception:  # noqa: BLE001
                    ranges = [(int(func.start), int(func.start) + 1)]

            def _in_function(address: int) -> bool:
                return address != 0 and any(start <= address < end for start, end in ranges)

            def _to_file(address: Any) -> int | None:
                try:
                    tool_addr = int(address)
                except (TypeError, ValueError, OverflowError):
                    return None
                if not _in_function(tool_addr):
                    return None
                return (tool_addr - int(func.start)) + file_addr

            def _walk() -> tuple[str, list[LineMapping], dict[int, set[int]]]:
                settings = bn.DisassemblySettings()
                for option in (
                    bn.DisassemblyOption.ShowVariableTypesWhenAssigned,
                    bn.DisassemblyOption.GroupLinearDisassemblyFunctions,
                    bn.DisassemblyOption.WaitForIL,
                ):
                    settings.set_option(option)
                lvo = bn.LinearViewObject.single_function_language_representation(
                    func,
                    settings,
                    "Pseudo C",
                )
                cursor = bn.LinearViewCursor(lvo)
                cursor.seek_to_begin()
                rendered_rows: list[str] = []
                line_to_addrs: dict[int, set[int]] = {}
                variable_lines: dict[int, set[int]] = {}
                output_line = 1
                for _ in range(100000):
                    for row in cursor.lines:
                        if getattr(row, "type", None) in skipped_types:
                            continue
                        contents = getattr(row, "contents", row)
                        tokens = [
                            token
                            for token in getattr(contents, "tokens", ())
                            if getattr(token, "type", None) != InstructionTextTokenType.TagToken
                        ]
                        row_text = (
                            "".join(str(token) for token in tokens)
                            if hasattr(contents, "tokens")
                            else str(contents)
                        )
                        rendered_rows.append(row_text)
                        row_addr = _to_file(getattr(contents, "address", None))
                        if row_addr is not None:
                            line_to_addrs.setdefault(output_line, set()).add(row_addr)

                        relative_line = 0
                        for token in tokens:
                            token_type = getattr(token, "type", None)
                            token_line = output_line + relative_line
                            token_addresses = [getattr(token, "address", None)]
                            try:
                                expression = func.hlil.get_expr(int(token.il_expr_index))
                                token_addresses.append(getattr(expression, "address", None))
                            except Exception:  # noqa: BLE001
                                pass
                            for address in token_addresses:
                                token_addr = _to_file(address)
                                if token_addr is not None:
                                    line_to_addrs.setdefault(token_line, set()).add(token_addr)
                            if token_type in variable_types:
                                try:
                                    index = variable_indices.get(int(token.value))
                                except (TypeError, ValueError, OverflowError):
                                    index = None
                                if index is not None:
                                    variable_lines.setdefault(index, set()).add(token_line)
                            relative_line += str(getattr(token, "text", "")).count("\n")
                        output_line += row_text.count("\n") + 1
                    if not cursor.next():
                        break
                return (
                    "\n".join(rendered_rows),
                    common.merge_line_addresses(line_to_addrs),
                    variable_lines,
                )

            # binja generates HLIL lazily per function, so linear view returns a literal
            # 'Loading...' placeholder until it is touched — without this, nearly every
            # function in a large binary renders as Loading and gets dropped.
            with contextlib.suppress(Exception):
                _ = func.hlil
                _ = len(list(func.hlil.instructions))

            text, line_mappings, variable_lines = _walk()
            # A still-placeholder body is a FAILURE rather than junk that would pollute
            # GED/byte_match.
            if not text.strip() or "Loading..." in text:
                with contextlib.suppress(Exception):
                    func.view.update_analysis_and_wait()
                text, line_mappings, variable_lines = _walk()
            if text.strip() and "Loading..." not in text:
                return text, line_mappings, variable_lines
        except Exception:  # noqa: BLE001
            pass
        return "", [], {}

    @staticmethod
    def _extract_variables(func: Any) -> list[VariableInfo]:
        variables, _variable_indices = RawBinjaDecompiler._extract_variables_with_identifiers(func)
        return variables

    @staticmethod
    def _extract_variables_with_identifiers(
        func: Any,
    ) -> tuple[list[VariableInfo], dict[int, int]]:
        """Pull arguments (ABI order) and stack vars from binja's Variables.

        ``func.parameter_vars`` lists arguments in ABI order; ``func.vars`` lists
        all variables. A binja ``Variable`` has ``name``, ``type`` (with
        ``.width``), and a ``storage`` that is a frame offset for stack vars
        (``source_type == VariableSourceType.StackVariableSourceType``).
        """
        variables: list[VariableInfo] = []
        variable_indices: dict[int, int] = {}
        param_set: set[Any] = set()
        try:
            params = list(func.parameter_vars)
        except Exception:  # noqa: BLE001
            params = []

        for idx, var in enumerate(params):
            param_set.add(var)
            with contextlib.suppress(Exception):
                variable_indices[int(var.identifier)] = len(variables)
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
            with contextlib.suppress(Exception):
                variable_indices[int(var.identifier)] = len(variables)
            variables.append(
                VariableInfo(
                    name=str(getattr(var, "name", "") or ""),
                    type=RawBinjaDecompiler._type_str(var),
                    stack_offset=stack_offset,
                    size=RawBinjaDecompiler._var_size(var),
                    kind="stack",
                )
            )
        return variables, variable_indices

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
        """Compatibility wrapper using the canonical Pseudo-C cursor."""
        _code, mappings, _variable_lines = RawBinjaDecompiler._render_c_with_evidence(
            func,
            file_addr,
            {},
        )
        return mappings
