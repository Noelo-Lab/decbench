"""Raw angr decompiler backend (no declib).

Drives angr's native decompilation pipeline directly:

* ``angr.Project(path, auto_load_libs=False)``
* ``proj.analyses.CFGFast(normalize=True)`` for function discovery
* ``proj.analyses.Decompiler(func, cfg=cfg.model)`` per function

and produces the same :class:`DecompilationResult` shape as the declib-backed
``AngrDeclibDecompiler``:

* function addresses translated to **ELF-file space** (``lifted + elf_base``),
* :class:`VariableInfo` for arguments (with ABI ``arg_index``) and stack/locals,
* best-effort line mappings from the codegen position map, and
* gotos/bools structure metadata.
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


@register_decompiler("angr")
class RawAngrDecompiler(Decompiler):
    """angr's decompiler driven natively, without declib."""

    name = "angr"
    display_name = "angr"

    # Which structuring algorithm to drive angr with. ``None`` uses angr's
    # default (currently SAILR). Subclasses set this to "Phoenix"/"DREAM" to
    # benchmark a specific structurer as its own decompiler (see RawAngrPhoenix).
    structurer: str | None = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        try:
            import angr  # noqa: F401

            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            import angr

            return str(angr.__version__)
        except Exception:  # noqa: BLE001
            return "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover (name, ELF-space addr) for benchmarkable functions."""
        if not self.is_available():
            return []
        try:
            import angr

            proj = angr.Project(str(binary_path), auto_load_libs=False)
            proj.analyses.CFGFast(normalize=True)
            elf_base = common.elf_min_vaddr(binary_path)
            text_range = common.elf_text_range(binary_path)
            return self._enumerate(proj, elf_base, text_range)
        except Exception as e:  # noqa: BLE001
            _l.error("angr-raw: failed to discover functions in %s: %s", binary_path, e)
            return []

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary with angr natively.

        Args mirror ``declib_dec``: ``function_names`` narrows to the project's
        own source functions; ``progress_path`` atomically pickles the partial
        result after each function so a killed process is recoverable.
        """
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        import angr

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "angr", "via": "raw"}
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
            proj = angr.Project(str(binary_path), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)

            if functions is not None:
                # Caller addresses are ELF-space; angr keys functions by the
                # binary's own (loaded) address, which for a non-PIE static
                # ELF equals the ELF-space address. We look up by address.
                target_funcs = [(n, a) for (n, a) in functions]
            else:
                target_funcs = self._enumerate(proj, elf_base, text_range)

            target_funcs = common.narrow_to_source(
                target_funcs,
                function_names,
                backend="angr",
                binary_name=binary_path.name,
            )

            for func_name, file_addr in target_funcs:
                func_result = None
                try:
                    func_result = self._decompile_one(proj, cfg, func_name, file_addr, elf_base)
                except Exception as e:  # noqa: BLE001
                    _l.debug("angr-raw: failed to decompile %s: %s", func_name, e)

                if func_result is not None:
                    decompiled_functions[func_name] = func_result
                else:
                    failed_functions.append(func_name)
                _dump()

        except Exception as e:  # noqa: BLE001
            _l.error("angr-raw failed on %s: %s", binary_path, e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra={"error": str(e), "backend": "angr", "via": "raw"},
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

    #
    # angr helpers
    #

    def _enumerate(
        self,
        proj: Any,
        elf_base: int,
        text_range: tuple[int, int] | None,
    ) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-space addr) for benchmarkable functions.

        angr's ``func.addr`` is in the binary's loaded address space. For the
        static, non-PIE ELFs DecBench builds, the load base equals
        ``min(PT_LOAD vaddr)``, so the loaded address already equals the
        ELF-file-space address. We nonetheless go via the lifted offset
        (``addr - load_base``) + ``elf_base`` to be robust if angr rebased.
        """
        load_base = self._angr_load_base(proj)
        out: list[tuple[str, int]] = []
        for func in proj.kb.functions.values():
            if func.is_plt or func.is_simprocedure or func.is_alignment:
                continue
            name = func.name or ""
            file_addr = (int(func.addr) - load_base) + elf_base
            if common.should_skip_function(name, file_addr, text_range):
                continue
            out.append((name, file_addr))
        return sorted(out, key=lambda x: x[1])

    @staticmethod
    def _angr_load_base(proj: Any) -> int:
        """The address angr loaded the main object at (its min mapped vaddr)."""
        try:
            return int(proj.loader.main_object.mapped_base) or int(proj.loader.main_object.min_addr)
        except Exception:  # noqa: BLE001
            return 0

    def _decompile_one(
        self,
        proj: Any,
        cfg: Any,
        func_name: str,
        file_addr: int,
        elf_base: int,
    ) -> FunctionDecompilation | None:
        """Decompile one function -> FunctionDecompilation (ELF-space addr)."""
        load_base = self._angr_load_base(proj)
        # ELF-space -> angr loaded address.
        angr_addr = (file_addr - elf_base) + load_base
        try:
            func = proj.kb.functions.get_by_addr(angr_addr)
        except KeyError:
            func = proj.kb.functions.function(name=func_name)
            if func is None:
                return None

        dec_kwargs: dict[str, Any] = {"cfg": cfg.model}
        if self.structurer is not None:
            # Select a specific structuring algorithm via angr's options system
            # (value is convert()ed to the structurer class by the option).
            from angr.analyses.decompiler.decompilation_options import (
                get_structurer_option,
            )

            opt = get_structurer_option()
            if opt is not None:
                dec_kwargs["options"] = [(opt, self.structurer)]
        dec = proj.analyses.Decompiler(func, **dec_kwargs)
        codegen = getattr(dec, "codegen", None)
        if codegen is None or not getattr(codegen, "text", None):
            return None
        code = codegen.text

        variables = self._extract_variables(codegen, proj, func)
        line_mappings = self._extract_line_mappings(codegen, code, elf_base, load_base)
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
    def _type_str(simtype: Any) -> str:
        """Best-effort C type string for an angr SimType."""
        if simtype is None:
            return ""
        for attr in ("c_repr",):
            fn = getattr(simtype, attr, None)
            if callable(fn):
                try:
                    return str(fn()).strip()
                except Exception:  # noqa: BLE001
                    pass
        try:
            return str(simtype).strip()
        except Exception:  # noqa: BLE001
            return ""

    def _extract_variables(self, codegen: Any, proj: Any, func: Any) -> list[VariableInfo]:
        """Pull arguments (ABI order) and stack/local variables.

        Arguments come from ``cfunc.arg_list`` (preserving ABI order, so the
        type metric can match positionally even when angr names them ``a0`` /
        ``a1``). Locals come from ``cfunc.get_unified_local_vars()``, which maps
        each unified SimVariable to ``{(CVariable, SimType)}``; stack vars carry
        their (negative) frame offset.
        """
        from angr.sim_variable import SimStackVariable

        variables: list[VariableInfo] = []
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return variables

        # --- Arguments, in ABI/positional order. ---
        arg_list = getattr(cfunc, "arg_list", None) or []
        for position, cvar in enumerate(arg_list):
            simvar = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            name = (
                getattr(cvar, "name", None)
                or (getattr(simvar, "name", None) if simvar else None)
                or ""
            )
            vtype = self._type_str(
                getattr(cvar, "variable_type", None) or getattr(cvar, "type", None)
            )
            size = getattr(simvar, "size", None) if simvar is not None else None
            variables.append(
                VariableInfo(
                    name=name,
                    type=vtype,
                    stack_offset=None,
                    size=int(size) if isinstance(size, int) else None,
                    kind="arg",
                    arg_index=position,
                )
            )

        # --- Locals (stack & register), excluding the args already emitted. ---
        try:
            local_map = cfunc.get_unified_local_vars()
        except Exception:  # noqa: BLE001
            local_map = {}

        for simvar, cvar_types in (local_map or {}).items():
            vtype = ""
            for _cvar, simtype in cvar_types:
                vtype = self._type_str(simtype)
                if vtype:
                    break
            stack_offset = None
            if isinstance(simvar, SimStackVariable):
                stack_offset = int(simvar.offset) if simvar.offset is not None else None
            size = getattr(simvar, "size", None)
            variables.append(
                VariableInfo(
                    name=getattr(simvar, "name", None) or "",
                    type=vtype,
                    stack_offset=stack_offset,
                    size=int(size) if isinstance(size, int) else None,
                    kind="stack",
                )
            )

        return variables

    @staticmethod
    def _extract_line_mappings(
        codegen: Any,
        code: str,
        elf_base: int,
        load_base: int,
    ) -> list[LineMapping]:
        """Best-effort line mappings from the codegen position map.

        ``map_pos_to_addr`` maps character positions in ``text`` to AST nodes
        whose ``tags['ins_addr']`` is the originating instruction address (in
        angr's loaded space). We bucket those by 1-based line number and
        translate each address to ELF-file space. Returns ``[]`` if the map is
        unavailable.
        """
        posmap = getattr(codegen, "map_pos_to_addr", None)
        if posmap is None or not hasattr(posmap, "items"):
            return []

        starts = common.line_starts(code)
        line_to_addrs: dict[int, set[int]] = {}
        try:
            items = list(posmap.items())
        except Exception:  # noqa: BLE001
            return []

        for pos, element in items:
            obj = getattr(element, "obj", None)
            tags = getattr(obj, "tags", None) if obj is not None else None
            if not tags:
                continue
            ins_addr = tags.get("ins_addr")
            if ins_addr is None:
                continue
            try:
                file_addr = (int(ins_addr) - load_base) + elf_base
            except Exception:  # noqa: BLE001
                continue
            line_no = common.pos_to_line(int(pos), starts)
            line_to_addrs.setdefault(line_no, set()).add(file_addr)

        return common.merge_line_addresses(line_to_addrs)


@register_decompiler("phoenix")
class RawAngrPhoenixDecompiler(RawAngrDecompiler):
    """angr driven with the **Phoenix** structuring algorithm.

    Same native angr pipeline as :class:`RawAngrDecompiler`, but forces the
    Phoenix structurer instead of angr's default (SAILR), so the two appear as
    distinct decompilers in the benchmark.
    """

    name = "phoenix"
    display_name = "angr (Phoenix)"
    structurer = "Phoenix"
