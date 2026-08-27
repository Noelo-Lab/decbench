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
import shutil
import tempfile
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
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
    with_variable_occurrence_policy,
)

_l = logging.getLogger(__name__)


def _runtime_reloc_data_header(binary_path: Path) -> tuple[int, bytes] | None:
    """Find one stripped ARM copy-down section that ELF mislabeled as relocations.

    Some embedded linker scripts call their initialized RAM data output section
    ``.relocate``. GNU ld then gives that section ``SHT_REL`` even though its bytes
    are ordinary copy-down data. Once ``strip --strip-all`` removes ``.symtab``,
    CLE tries to parse those bytes as relocations and rejects the binary. Match
    only the exact invalid, allocated data layout and return the section-header
    type field plus its ``SHT_PROGBITS`` replacement.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with binary_path.open("rb") as stream:
            elf = ELFFile(stream)
            if (
                elf.elfclass != 32
                or not elf.little_endian
                or elf.header["e_type"] != "ET_EXEC"
                or elf.header["e_machine"] != "EM_ARM"
            ):
                return None
            sections = list(elf.iter_sections())
            if any(section.header["sh_type"] == "SHT_SYMTAB" for section in sections):
                return None
            data_segments = [
                segment
                for segment in elf.iter_segments()
                if segment.header["p_type"] == "PT_LOAD"
                and int(segment.header["p_flags"]) == 0x6
                and int(segment.header["p_filesz"]) > 0
                and int(segment.header["p_paddr"]) != int(segment.header["p_vaddr"])
            ]
            candidates: list[int] = []
            for index, section in enumerate(sections):
                header = section.header
                if (
                    section.name != ".relocate"
                    or header["sh_type"] != "SHT_REL"
                    or int(header["sh_flags"]) != 0x3
                    or int(header["sh_link"]) != 0
                    or int(header["sh_info"]) != 0
                    or int(header["sh_entsize"]) != 8
                    or int(header["sh_size"]) == 0
                    or int(header["sh_size"]) % 8
                ):
                    continue
                section_offset = int(header["sh_offset"])
                section_address = int(header["sh_addr"])
                section_size = int(header["sh_size"])
                if not any(
                    section_offset == int(segment.header["p_offset"])
                    and section_address == int(segment.header["p_vaddr"])
                    and section_offset + section_size
                    <= int(segment.header["p_offset"]) + int(segment.header["p_filesz"])
                    and section_address + section_size
                    <= int(segment.header["p_vaddr"]) + int(segment.header["p_memsz"])
                    for segment in data_segments
                ):
                    continue
                candidates.append(
                    int(elf.header["e_shoff"]) + index * int(elf.header["e_shentsize"]) + 4
                )
    except Exception as error:  # noqa: BLE001
        _l.debug("angr-raw: could not inspect ELF section metadata for %s: %s", binary_path, error)
        return None
    if len(candidates) != 1:
        return None
    return candidates[0], (1).to_bytes(4, byteorder="little")


@contextmanager
def _angr_input_binary(binary_path: Path) -> Iterator[tuple[Path, int]]:
    """Yield an angr-loadable path without ever changing the benchmark artifact."""
    patch = _runtime_reloc_data_header(binary_path)
    if patch is None:
        yield binary_path, 0
        return

    with tempfile.TemporaryDirectory(prefix="decbench-angr-elf-") as temp_dir:
        analysis_path = Path(temp_dir) / binary_path.name
        shutil.copy2(binary_path, analysis_path)
        offset, replacement = patch
        with analysis_path.open("r+b") as stream:
            stream.seek(offset)
            if stream.read(len(replacement)) != (9).to_bytes(4, byteorder="little"):
                raise ValueError("ELF section type changed while preparing angr input")
            stream.seek(offset)
            stream.write(replacement)
        _l.warning(
            "angr-raw: treating malformed allocated .relocate as data in a temporary " "copy of %s",
            binary_path,
        )
        yield analysis_path, 1


@register_decompiler("angr")
class RawAngrDecompiler(Decompiler):
    """angr's decompiler driven natively, without declib."""

    name = "angr"
    display_name = "angr"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

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

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
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
        code_ranges = common.executable_code_ranges(binary_path)
        addr_targets = common.addr_targets_of(function_names)
        input_repair_count = 0

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "angr", "via": "raw"}
            if input_repair_count:
                extra["elf_runtime_data_section_retyped"] = input_repair_count
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
            with _angr_input_binary(binary_path) as (analysis_path, repair_count):
                input_repair_count = repair_count
                proj = angr.Project(str(analysis_path), auto_load_libs=False)
                cfg = proj.analyses.CFGFast(normalize=True)

                if functions is not None:
                    # angr keys functions by loaded address, which equals the caller's ELF-space
                    # address for a non-PIE static ELF.
                    target_funcs = [(n, a) for (n, a) in functions]
                else:
                    target_funcs = self._enumerate(proj, elf_base, code_ranges, addr_targets)

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
            extra: dict[str, Any] = {
                "error": str(e),
                "backend": "angr",
                "via": "raw",
            }
            if input_repair_count:
                extra["elf_runtime_data_section_retyped"] = input_repair_count
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra=extra,
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

    def _enumerate(
        self,
        proj: Any,
        elf_base: int,
        code_ranges: common.CodeRangeFilter,
        addr_targets: set[int] | None = None,
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
            if common.should_skip_function(name, file_addr, code_ranges, addr_targets):
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
        angr_addr = (file_addr - elf_base) + load_base
        func = None
        lookup_addresses = [angr_addr]
        if self._is_thumb_address(proj, angr_addr | 1):
            lookup_addresses.append(angr_addr | 1)
        for lookup_addr in lookup_addresses:
            try:
                func = proj.kb.functions.get_by_addr(lookup_addr)
                break
            except KeyError:
                continue
        if func is None:
            func = proj.kb.functions.function(name=func_name)
            if func is None:
                return None
        is_thumb = self._is_thumb_address(proj, int(func.addr))

        dec_kwargs: dict[str, Any] = {"cfg": cfg.model}
        dec = proj.analyses.Decompiler(func, **dec_kwargs)
        codegen = getattr(dec, "codegen", None)
        if codegen is None or not getattr(codegen, "text", None):
            return None
        code = codegen.text

        variables, variable_aliases = self._extract_variables_with_aliases(codegen, proj, func)
        expansion, valid_addresses = self._instruction_evidence(dec, proj, func)
        line_mappings = self._extract_line_mappings(
            codegen,
            code,
            elf_base,
            load_base,
            instruction_expansion=expansion,
            valid_addresses=valid_addresses,
            is_thumb=is_thumb,
        )
        self._add_variable_evidence(
            variables,
            variable_aliases,
            codegen,
            code,
            line_mappings,
            function_name=func_name,
        )
        metadata = with_variable_occurrence_policy(common.extract_metrics(code), "exact")

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
    def _is_thumb_address(proj: Any, address: int) -> bool:
        predicate = getattr(getattr(proj, "arch", None), "is_thumb", None)
        try:
            return bool(predicate(address)) if callable(predicate) else bool(predicate)
        except Exception:  # noqa: BLE001
            return False

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
        variables, _variable_aliases = self._extract_variables_with_aliases(codegen, proj, func)
        return variables

    def _extract_variables_with_aliases(
        self,
        codegen: Any,
        proj: Any,
        func: Any,
    ) -> tuple[list[VariableInfo], list[tuple[Any, int]]]:
        """Pull arguments (ABI order) and stack/local variables.

        Arguments come from ``cfunc.arg_list`` (preserving ABI order, so the
        type metric can match positionally even when angr names them ``a0`` /
        ``a1``). Locals come from ``cfunc.get_unified_local_vars()``, which maps
        each unified SimVariable to ``{(CVariable, SimType)}``; stack vars carry
        their (negative) frame offset.
        """
        from angr.sim_variable import SimStackVariable

        variables: list[VariableInfo] = []
        variable_aliases: list[tuple[Any, int]] = []
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return variables, variable_aliases

        arg_list = getattr(cfunc, "arg_list", None) or []
        argument_aliases: list[Any] = []
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
            index = len(variables)
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
            for alias in (
                getattr(cvar, "unified_variable", None),
                getattr(cvar, "variable", None),
                simvar,
            ):
                if alias is not None:
                    variable_aliases.append((alias, index))
                    argument_aliases.append(alias)

        try:
            local_map = cfunc.get_unified_local_vars()
        except Exception:  # noqa: BLE001
            local_map = {}

        for simvar, cvar_types in (local_map or {}).items():
            if any(simvar is alias or simvar == alias for alias in argument_aliases):
                continue
            vtype = ""
            for _cvar, simtype in cvar_types:
                vtype = self._type_str(simtype)
                if vtype:
                    break
            stack_offset = None
            if isinstance(simvar, SimStackVariable):
                stack_offset = int(simvar.offset) if simvar.offset is not None else None
            size = getattr(simvar, "size", None)
            index = len(variables)
            variables.append(
                VariableInfo(
                    name=getattr(simvar, "name", None) or "",
                    type=vtype,
                    stack_offset=stack_offset,
                    size=int(size) if isinstance(size, int) else None,
                    kind="stack",
                )
            )
            variable_aliases.append((simvar, index))
            for cvar, _simtype in cvar_types:
                for alias in (
                    getattr(cvar, "unified_variable", None),
                    getattr(cvar, "variable", None),
                ):
                    if alias is not None:
                        variable_aliases.append((alias, index))

        return variables, variable_aliases

    @staticmethod
    def _instruction_evidence(
        dec: Any,
        proj: Any,
        func: Any,
    ) -> tuple[dict[int, set[int]], set[int]]:
        """Expand AIL statement provenance to the machine instructions it represents."""
        valid_addresses: set[int] = set()
        try:
            for block in func.blocks:
                valid_addresses.update(int(address) for address in block.instruction_addrs)
        except Exception:  # noqa: BLE001
            pass

        graph = getattr(dec, "unoptimized_ail_graph", None)
        if graph is None:
            graph = getattr(getattr(dec, "clinic", None), "cc_graph", None)
        try:
            nodes = list(graph.nodes)
        except Exception:  # noqa: BLE001
            return {}, valid_addresses

        expansion: dict[int, set[int]] = defaultdict(set)
        for ail_block in nodes:
            try:
                vex_block = proj.factory.block(int(ail_block.addr))
                instruction_addrs = [int(address) for address in vex_block.instruction_addrs]
                statements = [
                    statement
                    for statement in ail_block.statements
                    if getattr(statement, "ins_addr", None) is not None
                    and statement.__class__.__name__ != "Label"
                ]
            except Exception:  # noqa: BLE001
                continue
            if not statements:
                continue
            statement_index = 0
            for instruction_addr in instruction_addrs:
                statement_addr = int(statements[statement_index].ins_addr)
                expansion[statement_addr].add(instruction_addr)
                if instruction_addr == statement_addr:
                    statement_index += 1
                if statement_index >= len(statements):
                    break
        return dict(expansion), valid_addresses

    @staticmethod
    def _position_start(position: Any) -> int | None:
        value = getattr(position, "start", position)
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _add_variable_evidence(
        variables: list[VariableInfo],
        variable_aliases: list[tuple[Any, int]],
        codegen: Any,
        code: str,
        line_mappings: list[LineMapping],
        *,
        function_name: str | None = None,
    ) -> None:
        starts = common.line_starts(code)
        variable_lines: dict[int, set[int]] = defaultdict(set)
        native_map = getattr(codegen, "map_ast_to_pos", None)
        try:
            native_items = list(native_map.items())
        except Exception:  # noqa: BLE001
            native_items = []
        for ast_variable, positions in native_items:
            indices: set[int] = set()
            for alias, index in variable_aliases:
                try:
                    matches = ast_variable is alias or ast_variable == alias
                except Exception:  # noqa: BLE001
                    matches = ast_variable is alias
                if matches:
                    indices.add(index)
            if not indices:
                continue
            if not isinstance(positions, (set, list, tuple)):
                positions = (positions,)
            for position in positions:
                start = RawAngrDecompiler._position_start(position)
                if start is None or start < 0 or start >= len(code):
                    continue
                line_no = common.pos_to_line(start, starts)
                for index in indices:
                    variable_lines[index].add(line_no)

        try:
            from decbench.metrics.variable_features import variable_occurrence_lines

            occurrence_lines = variable_occurrence_lines(
                code,
                function_name or "",
                (variable.name for variable in variables),
                require_exact_function_name=function_name is not None,
            )
        except Exception as e:
            _l.debug("Could not join angr variable occurrences in %s: %s", function_name, e)
            occurrence_lines = {}
        for index, variable in enumerate(variables):
            if variable_lines.get(index) or not variable.name:
                continue
            variable_lines[index].update(occurrence_lines.get(variable.name, ()))

        line_addresses = {mapping.line_number: set(mapping.addresses) for mapping in line_mappings}
        for index, lines in variable_lines.items():
            variables[index].line_numbers = sorted(lines)
            variables[index].addresses = sorted(
                {address for line in lines for address in line_addresses.get(line, set())}
            )

    @staticmethod
    def _mask_nonidentifiers(code: str) -> str:
        """Blank comments and literals while preserving character positions and newlines."""
        chars = list(code)
        index = 0
        state: str | None = None
        while index < len(chars):
            current = chars[index]
            following = chars[index + 1] if index + 1 < len(chars) else ""
            if state is None:
                if current == "/" and following == "/":
                    chars[index] = chars[index + 1] = " "
                    state = "line"
                    index += 2
                    continue
                if current == "/" and following == "*":
                    chars[index] = chars[index + 1] = " "
                    state = "block"
                    index += 2
                    continue
                if current in {'"', "'"}:
                    chars[index] = " "
                    state = current
                    index += 1
                    continue
            elif state == "line":
                if current == "\n":
                    state = None
                else:
                    chars[index] = " "
                index += 1
                continue
            elif state == "block":
                if current == "*" and following == "/":
                    chars[index] = chars[index + 1] = " "
                    state = None
                    index += 2
                    continue
                if current != "\n":
                    chars[index] = " "
                index += 1
                continue
            else:
                quote = state
                if current == "\\" and following:
                    chars[index] = " "
                    if following != "\n":
                        chars[index + 1] = " "
                    index += 2
                    continue
                if current == quote:
                    chars[index] = " "
                    state = None
                elif current != "\n":
                    chars[index] = " "
                index += 1
                continue
            index += 1
        return "".join(chars)

    @staticmethod
    def _extract_line_mappings(
        codegen: Any,
        code: str,
        elf_base: int,
        load_base: int,
        *,
        instruction_expansion: dict[int, set[int]] | None = None,
        valid_addresses: set[int] | None = None,
        is_thumb: bool = False,
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
        normalized_valid = (
            {int(address) & ~1 if is_thumb else int(address) for address in valid_addresses}
            if valid_addresses
            else None
        )
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
            line_no = common.pos_to_line(int(pos), starts)
            tool_addresses = (instruction_expansion or {}).get(int(ins_addr), {int(ins_addr)})
            if is_thumb and int(ins_addr) not in (instruction_expansion or {}):
                tool_addresses = (instruction_expansion or {}).get(
                    int(ins_addr) | 1, tool_addresses
                )
                tool_addresses = (instruction_expansion or {}).get(
                    int(ins_addr) & ~1, tool_addresses
                )
            for tool_address in tool_addresses:
                normalized = int(tool_address) & ~1 if is_thumb else int(tool_address)
                if normalized_valid is not None and normalized not in normalized_valid:
                    continue
                file_addr = (normalized - load_base) + elf_base
                line_to_addrs.setdefault(line_no, set()).add(file_addr)

        return common.merge_line_addresses(line_to_addrs)
