"""Raw IDA Pro / Hex-Rays decompiler backend (no declib), via ``idalib``.

Drives IDA's headless library (``idapro``/``idalib``, IDA 9+) and the Hex-Rays
decompiler API directly:

* ``idapro.open_database(path, run_auto_analysis=True)``
* iterate functions with ``idautils.Functions()`` / ``ida_funcs``
* decompile each with ``ida_hexrays.decompile(ea)`` -> ``cfunc``
* C text from ``str(cfunc)``
* variables from ``cfunc.lvars`` (args carry ``is_arg_var``; stack lvars carry
  a frame location), with argument POSITIONS taken from ``cfunc.argidx`` —
  ``get_lvars()`` enumerates in allocation order, not declared order

Availability is detected at runtime and requires a working IDA 9+ ``idalib``.
The module never imports IDA at import time.
"""

from __future__ import annotations

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

# Order matters (__int64 before __int). Mirrors declib_dec.IDADeclibDecompiler
# so byte_match can recompile the output.
_CODE_REPLACEMENTS = (
    ("unsigned __int64", "unsigned long long"),
    ("__int64", "long long"),
    ("__int32", "int"),
    ("__int16", "short"),
    ("__int8", "char"),
    ("_QWORD", "long long"),
    ("_DWORD", "int"),
    ("_WORD", "short"),
    ("_BYTE", "char"),
    ("_BOOL8", "long long"),
    ("_BOOL4", "int"),
    ("_BOOL", "_Bool"),
    ("__cdecl ", ""),
    ("__fastcall ", ""),
    ("__stdcall ", ""),
    ("__thiscall ", ""),
    ("__usercall ", ""),
    ("__golang ", ""),
    ("__noreturn ", ""),
)


@register_decompiler("ida")
class RawIDADecompiler(Decompiler):
    """IDA Pro (Hex-Rays) driven natively via idalib, without declib."""

    name = "ida"
    display_name = "IDA Pro"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    def is_available(self) -> bool:
        """Whether a real, working IDA 9+ idalib is importable.

        We require both ``idapro`` (the headless entry point) and
        ``ida_hexrays`` (the decompiler). Importing ``idapro`` alone is not
        enough, so we also require the Hex-Rays module.

        Order matters: ``idapro`` must be imported *first* — its ``__init__``
        injects IDA's ``python`` directory onto ``sys.path``, which is what
        makes ``ida_hexrays`` (and the other ``ida_*`` modules) importable. We
        use ``importlib`` rather than ``import`` statements so the linter cannot
        reorder them alphabetically (which would put ``ida_hexrays`` first and
        make this spuriously report unavailable on a cold process).
        """
        import importlib

        try:
            importlib.import_module("idapro")
            importlib.import_module("ida_hexrays")
            return True
        except Exception:  # noqa: BLE001 - license/binary errors, not just ImportError
            return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            import idaapi

            return str(idaapi.IDA_SDK_VERSION)
        except Exception:  # noqa: BLE001
            return "unknown"

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

        import ida_hexrays
        import idapro

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "ida", "via": "raw"}
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

        try:
            idapro.open_database(str(binary_path), run_auto_analysis=True)
            if not ida_hexrays.init_hexrays_plugin():
                raise RuntimeError("Hex-Rays decompiler not available")
            try:
                enumerated = self._enumerate(elf_base, text_range)
                if functions is not None:
                    requested = {n for (n, _a) in functions}
                    enumerated = [(n, a) for (n, a) in enumerated if n in requested]
                enumerated = common.narrow_to_source(
                    enumerated,
                    function_names,
                    backend="ida",
                    binary_name=binary_path.name,
                )
                for func_name, file_addr in enumerated:
                    func_result = None
                    try:
                        func_result = self._decompile_one(func_name, file_addr, elf_base)
                    except Exception as e:  # noqa: BLE001
                        _l.debug("ida-raw: failed to decompile %s: %s", func_name, e)
                    if func_result is not None:
                        decompiled_functions[func_name] = func_result
                    else:
                        failed_functions.append(func_name)
                    _dump()
            finally:
                idapro.close_database(save=False)

        except Exception as e:  # noqa: BLE001
            _l.error("ida-raw failed on %s: %s", binary_path, e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra={"error": str(e), "backend": "ida", "via": "raw"},
                ),
            )

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
    def _ida_image_base() -> int:
        """The address IDA loaded the binary at (its image base)."""
        try:
            import idaapi

            return int(idaapi.get_imagebase())
        except Exception:  # noqa: BLE001
            return 0

    def _enumerate(
        self,
        elf_base: int,
        text_range: tuple[int, int] | None,
    ) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-space addr) for benchmarkable functions.

        IDA loads non-relocatable ELFs at their link address; for PIE/ET_DYN it
        uses its own image base. We translate each EA via
        ``ea - image_base + elf_base`` so addresses land in ELF-file space (the
        space DWARF uses), consistent with the angr/Ghidra backends.
        """
        import ida_funcs
        import ida_name
        import idautils

        image_base = self._ida_image_base()
        out: list[tuple[str, int]] = []
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            if f is None:
                continue
            if f.flags & ida_funcs.FUNC_THUNK:
                continue
            name = ida_name.get_ea_name(ea) or ""
            file_addr = (int(ea) - image_base) + elf_base
            if common.should_skip_function(name, file_addr, text_range):
                continue
            out.append((name, file_addr))
        return sorted(out, key=lambda x: x[1])

    def _decompile_one(
        self,
        func_name: str,
        file_addr: int,
        elf_base: int,
    ) -> FunctionDecompilation | None:
        """Decompile one function with Hex-Rays -> FunctionDecompilation."""
        import ida_hexrays

        ida_ea = (file_addr - elf_base) + self._ida_image_base()
        cfunc = ida_hexrays.decompile(ida_ea)
        if cfunc is None:
            return None
        code = self._normalize_code(str(cfunc))
        if not code:
            return None

        variables, local_indices = self._extract_variables_with_indices(cfunc)
        line_mappings = self._extract_line_mappings(
            cfunc,
            elf_base,
            self._ida_image_base(),
        )
        line_addresses = {mapping.line_number: set(mapping.addresses) for mapping in line_mappings}
        for local_index, lines in self._extract_variable_lines(cfunc).items():
            index = local_indices.get(local_index)
            if index is None:
                continue
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
    def _normalize_code(code: str) -> str:
        """Normalize IDA-specific types/annotations to standard C."""
        for old, new in _CODE_REPLACEMENTS:
            code = code.replace(old, new)
        return code

    @staticmethod
    def _arg_positions(cfunc: Any, lvars: Any) -> dict[int, int]:
        """``lvar index -> ABI argument position`` from ``cfunc.argidx``.

        ``get_lvars()`` enumerates in Hex-Rays' internal allocation order, which
        is NOT the declared argument order — on leveldb 53.8% of IDA's multi-arg
        functions came out permuted (``ClipToRange`` yields ``a3, a1, a2``).
        Since type_match matches arguments by ABI position, that silently
        mis-scored IDA. ``cfunc_t::argidx`` is the canonical argument order; we
        fall back to the enumeration order only if it is unavailable.
        """
        try:
            order = [int(i) for i in cfunc.argidx]
        except Exception:  # noqa: BLE001
            order = []
        if not order:
            order = [i for i, lv in enumerate(lvars) if bool(getattr(lv, "is_arg_var", False))]
        return {lvar_index: pos for pos, lvar_index in enumerate(order)}

    @staticmethod
    def _extract_variables(cfunc: Any) -> list[VariableInfo]:
        variables, _local_indices = RawIDADecompiler._extract_variables_with_indices(cfunc)
        return variables

    @staticmethod
    def _extract_variables_with_indices(
        cfunc: Any,
    ) -> tuple[list[VariableInfo], dict[int, int]]:
        """Pull arguments (ABI order) and stack locals from ``cfunc.lvars``.

        Hex-Rays ``lvar_t`` objects expose ``is_arg_var``, ``name``, ``width``
        (size in bytes), ``type()`` (a ``tinfo_t`` whose ``_print()``/``dstr()``
        gives a C type), and ``location`` for stack vars (``is_stk_off()`` /
        ``stkoff()``). Argument POSITIONS come from ``cfunc.argidx``, not from
        the enumeration order (see :meth:`_arg_positions`).
        """
        variables: list[VariableInfo] = []
        local_indices: dict[int, int] = {}
        try:
            lvars = cfunc.get_lvars()
        except Exception:  # noqa: BLE001
            return variables, local_indices

        arg_positions = RawIDADecompiler._arg_positions(cfunc, lvars)
        fallback_position = len(arg_positions)
        try:
            stack_delta = int(cfunc.get_stkoff_delta())
        except Exception:  # noqa: BLE001
            stack_delta = 0
        for lvar_index, lvar in enumerate(lvars):
            try:
                name = str(getattr(lvar, "name", "") or "")
                tinfo = lvar.type() if hasattr(lvar, "type") else None
                type_str = ""
                if tinfo is not None:
                    try:
                        type_str = str(tinfo.dstr())
                    except Exception:  # noqa: BLE001
                        try:
                            type_str = str(tinfo._print())
                        except Exception:  # noqa: BLE001
                            type_str = ""
                size = int(lvar.width) if getattr(lvar, "width", None) else None
                is_arg = bool(getattr(lvar, "is_arg_var", False))
            except Exception:  # noqa: BLE001
                continue

            if is_arg:
                position = arg_positions.get(lvar_index)
                if position is None:
                    position = fallback_position
                    fallback_position += 1
                local_indices[lvar_index] = len(variables)
                variables.append(
                    VariableInfo(
                        name=name,
                        type=type_str,
                        stack_offset=None,
                        size=size,
                        kind="arg",
                        arg_index=position,
                    )
                )
            else:
                stack_offset = None
                try:
                    loc = lvar.location
                    if loc is not None and loc.is_stkoff():
                        stack_offset = int(loc.stkoff()) - stack_delta
                except Exception:  # noqa: BLE001
                    stack_offset = None
                local_indices[lvar_index] = len(variables)
                variables.append(
                    VariableInfo(
                        name=name,
                        type=type_str,
                        stack_offset=stack_offset,
                        size=size,
                        kind="stack",
                    )
                )
        return variables, local_indices

    @staticmethod
    def _extract_line_mappings(
        cfunc: Any,
        elf_base: int,
        image_base: int,
    ) -> list[LineMapping]:
        """Map 1-based pseudocode lines to ELF-file-space instruction addresses."""
        try:
            if not cfunc.get_pseudocode():
                return []
            eamap = cfunc.get_eamap()
        except Exception:  # noqa: BLE001
            return []

        line_to_addrs: dict[int, set[int]] = {1: {(int(cfunc.entry_ea) - image_base) + elf_base}}
        try:
            for ida_ea, items in eamap.items():
                file_addr = (int(ida_ea) - image_base) + elf_base
                for item in items:
                    try:
                        _x, zero_based_line = cfunc.find_item_coords(item)
                    except Exception:  # noqa: BLE001
                        continue
                    line_to_addrs.setdefault(int(zero_based_line) + 1, set()).add(file_addr)
        except Exception:  # noqa: BLE001
            return []

        return common.merge_line_addresses(line_to_addrs)

    @staticmethod
    def _extract_variable_lines(cfunc: Any) -> dict[int, set[int]]:
        try:
            import ida_hexrays
        except Exception:  # noqa: BLE001
            return {}

        variable_lines: dict[int, set[int]] = {}
        for item in cfunc.treeitems:
            try:
                if item.op != ida_hexrays.cot_var:
                    continue
                index = int(item.cexpr.v.idx)
                _x, zero_based_line = cfunc.find_item_coords(item)
                variable_lines.setdefault(index, set()).add(int(zero_based_line) + 1)
            except Exception:  # noqa: BLE001
                continue
        return variable_lines
