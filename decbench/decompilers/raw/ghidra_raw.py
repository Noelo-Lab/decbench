"""Raw Ghidra decompiler backend (no declib), driven via ``pyghidra``.

Drives Ghidra's headless decompiler directly:

* start the JVM with the right install via ``pyghidra.start()`` (install dir
  resolved from the versioned config, else ``GHIDRA_INSTALL_DIR``),
* open + auto-analyze the program with ``pyghidra.open_program``,
* per function: ``DecompInterface.decompileFunction(...).getDecompiledFunction().getC()``,
* variables from the ``HighFunction`` local symbol map (stack offset from
  storage), and
* best-effort line mappings from the Clang C-code markup (token line ->
  instruction address).

Multi-version support: ``version_settings('ghidra', self.requested_version)``
supplies an ``install_dir`` (set into ``GHIDRA_INSTALL_DIR`` before
``pyghidra.start()``), so ``ghidra@11.3`` vs ``ghidra@12.1`` launch different
installs.

Note: ``pyghidra.start()`` boots a single JVM per process and cannot switch
installs afterwards, so each *process* handles one Ghidra version / binary.
The run driver already spawns a fresh process per decompile task.
"""

from __future__ import annotations

import logging
import os
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


@register_decompiler("ghidra")
class RawGhidraDecompiler(Decompiler):
    """Ghidra driven natively via pyghidra, without declib."""

    name = "ghidra"
    display_name = "Ghidra"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    #
    # Version / install-dir resolution
    #

    def _install_dir(self) -> str | None:
        """Resolve which Ghidra install to launch.

        Prefers the per-version config (``decompilers.toml``), falls back to
        ``GHIDRA_INSTALL_DIR``.
        """
        from decbench.decompilers.spec import version_settings

        settings = version_settings("ghidra", self.requested_version)
        install = settings.get("install_dir")
        if install:
            return str(install)
        return os.environ.get("GHIDRA_INSTALL_DIR")

    def _ensure_started(self) -> None:
        """Point ``GHIDRA_INSTALL_DIR`` at the resolved install, then start JVM.

        Forces Java AWT headless mode: when ``DISPLAY`` is set but no usable X
        server is reachable, ``GhidraProject.createProject`` otherwise dies with
        an ``AWTError``. Setting ``-Djava.awt.headless=true`` (and clearing
        ``DISPLAY``) makes Ghidra run headless regardless of the environment.
        """
        install = self._install_dir()
        if install:
            os.environ["GHIDRA_INSTALL_DIR"] = install

        # Make Java run headless before the JVM boots.
        opts = os.environ.get("_JAVA_OPTIONS", "")
        if "java.awt.headless" not in opts:
            os.environ["_JAVA_OPTIONS"] = (
                opts + " -Djava.awt.headless=true"
            ).strip()
        # A stale DISPLAY (e.g. an old SSH X-forward) triggers the AWT error
        # even in "headless" Ghidra; drop it for this process.
        os.environ.pop("DISPLAY", None)

        import pyghidra

        if not pyghidra.started():
            pyghidra.start()

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        if self._install_dir() is None:
            return False
        try:
            import pyghidra  # noqa: F401

            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        install = self._install_dir()
        if install is None:
            return None
        try:
            version_file = Path(install) / "Ghidra" / "application.properties"
            with open(version_file) as f:
                for line in f:
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
        except Exception:  # noqa: BLE001
            pass
        return "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        if not self.is_available():
            return []
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)
        try:
            self._ensure_started()
            import pyghidra

            with pyghidra.open_program(str(binary_path), analyze=True) as flat:
                program = flat.getCurrentProgram()
                return self._enumerate(program, elf_base, text_range)
        except Exception as e:  # noqa: BLE001
            _l.error("ghidra-raw: failed to discover functions in %s: %s", binary_path, e)
            return []

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary with Ghidra natively (one program/JVM per process)."""
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []
        # Count of DWARF targets we force-created because auto-analysis missed
        # them (surfaced in metadata so discovery stays observable). Read as a
        # closure free variable by ``_meta`` below.
        forced_functions = 0

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "ghidra", "via": "raw"}
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

        try:
            self._ensure_started()
            import pyghidra
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            with pyghidra.open_program(str(binary_path), analyze=True) as flat:
                program = flat.getCurrentProgram()
                image_base = int(program.getImageBase().getOffset())

                requested = (
                    {n for (n, _a) in functions} if functions is not None else None
                )

                enumerated = self._enumerate(program, elf_base, text_range)
                if requested is not None:
                    enumerated = [(n, a) for (n, a) in enumerated if n in requested]

                enumerated = common.narrow_to_source(
                    enumerated, function_names, backend="ghidra",
                    binary_name=binary_path.name,
                )

                ifc = DecompInterface()
                ifc.openProgram(program)
                monitor = ConsoleTaskMonitor()
                timeout_s = int(self.config.function_timeout_seconds)
                # Map name -> ghidra Function for the enumerated set.
                by_name = self._functions_by_name(program)

                # Force-create DWARF targets Ghidra's auto-analysis missed (on
                # stripped firmware these are vector/pointer-table functions that
                # are never auto-promoted). This isolates decompilation quality
                # from boundary discovery: every backend gets the identical DWARF
                # target list. Only reached on the normal (non-timeout) path.
                covered = {a for (_n, a) in enumerated}
                for file_addr in common.missing_targets(covered, function_names, text_range):
                    try:
                        g_forced = self._force_create(program, file_addr, elf_base, image_base)
                    except Exception as e:  # noqa: BLE001
                        _l.debug("ghidra-raw: force-create at %#x failed: %s", file_addr, e)
                        continue
                    if g_forced is not None:
                        forced_name = str(g_forced.getName())
                        enumerated.append((forced_name, file_addr))
                        by_name[forced_name] = g_forced
                        forced_functions += 1

                for func_name, file_addr in enumerated:
                    func_result = None
                    g_func = by_name.get(func_name)
                    if g_func is not None:
                        try:
                            func_result = self._decompile_one(
                                ifc, g_func, func_name, file_addr,
                                elf_base, image_base, timeout_s, monitor,
                            )
                        except Exception as e:  # noqa: BLE001
                            _l.debug(
                                "ghidra-raw: failed to decompile %s: %s",
                                func_name, e,
                            )
                    if func_result is not None:
                        decompiled_functions[func_name] = func_result
                    else:
                        failed_functions.append(func_name)
                    _dump()

                ifc.dispose()

        except Exception as e:  # noqa: BLE001
            _l.error("ghidra-raw failed on %s: %s", binary_path, e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra={"error": str(e), "backend": "ghidra", "via": "raw"},
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
    # Ghidra helpers
    #

    def _enumerate(
        self,
        program: Any,
        elf_base: int,
        text_range: tuple[int, int] | None,
    ) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-space addr) for benchmarkable functions.

        Ghidra's ``getEntryPoint().getOffset()`` is already in the program's
        image-base address space, which equals ELF-file space for these
        binaries. We translate via ``offset - image_base + elf_base`` for
        robustness.
        """
        image_base = int(program.getImageBase().getOffset())
        out: list[tuple[str, int]] = []
        fm = program.getFunctionManager()
        for g_func in fm.getFunctions(True):
            if g_func.isThunk() or g_func.isExternal():
                continue
            name = g_func.getName() or ""
            offset = int(g_func.getEntryPoint().getOffset())
            file_addr = (offset - image_base) + elf_base
            if common.should_skip_function(name, file_addr, text_range):
                continue
            out.append((name, file_addr))
        return sorted(out, key=lambda x: x[1])

    @staticmethod
    def _functions_by_name(program: Any) -> dict[str, Any]:
        """Map (last-seen) function name -> Ghidra Function object."""
        out: dict[str, Any] = {}
        fm = program.getFunctionManager()
        for g_func in fm.getFunctions(True):
            out[g_func.getName()] = g_func
        return out

    @staticmethod
    def _force_create(
        program: Any,
        file_addr: int,
        elf_base: int,
        image_base: int,
    ) -> Any:
        """Disassemble + create a function at a DWARF target Ghidra missed.

        Returns the newly-created Ghidra ``Function`` (or ``None`` if creation
        failed). Runs inside a program transaction; on ARM it disassembles Thumb
        first (correct for Cortex-M firmware) and falls back to plain ARM.
        """
        from ghidra.app.cmd.disassemble import ArmDisassembleCommand, DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd

        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            (file_addr - elf_base) + image_base
        )
        listing = program.getListing()
        txid = program.startTransaction("decbench-force-decompile")
        try:
            if listing.getInstructionAt(addr) is None:
                if "ARM" in str(program.getLanguage().getProcessor()):
                    ArmDisassembleCommand(addr, None, True).applyTo(program)
                    if listing.getInstructionAt(addr) is None:
                        ArmDisassembleCommand(addr, None, False).applyTo(program)
                else:
                    DisassembleCommand(addr, None, True).applyTo(program)
            CreateFunctionCmd(addr).applyTo(program)
        finally:
            program.endTransaction(txid, True)
        return program.getFunctionManager().getFunctionAt(addr)

    def _decompile_one(
        self,
        ifc: Any,
        g_func: Any,
        func_name: str,
        file_addr: int,
        elf_base: int,
        image_base: int,
        timeout_s: int,
        monitor: Any,
    ) -> FunctionDecompilation | None:
        """Decompile one Ghidra function -> FunctionDecompilation."""
        res = ifc.decompileFunction(g_func, timeout_s, monitor)
        if res is None or not res.decompileCompleted():
            return None
        dfunc = res.getDecompiledFunction()
        if dfunc is None:
            return None
        code = dfunc.getC()
        if not code:
            return None

        high = res.getHighFunction()
        variables = self._extract_variables(high)
        line_mappings = self._extract_line_mappings(
            res, code, elf_base, image_base
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
    def _extract_variables(high: Any) -> list[VariableInfo]:
        """Pull arguments (ABI order) and stack locals from the HighFunction.

        Parameters are emitted first (ordered by their parameter ordinal, so
        ``arg_index`` matches DWARF's formal-parameter order); the rest become
        stack/locals. Stack offset comes from the variable's storage when it is
        stack-resident.
        """
        variables: list[VariableInfo] = []
        if high is None:
            return variables
        try:
            lsm = high.getLocalSymbolMap()
        except Exception:  # noqa: BLE001
            return variables
        if lsm is None:
            return variables

        params: list[tuple[int, VariableInfo]] = []
        locals_: list[VariableInfo] = []

        syms = lsm.getSymbols()
        while syms.hasNext():
            sym = syms.next()
            try:
                name = str(sym.getName() or "")
                dtype = sym.getDataType()
                type_str = str(dtype.getDisplayName()) if dtype is not None else ""
                size = int(sym.getSize()) if sym.getSize() is not None else None
                storage = sym.getStorage()
                is_stack = bool(storage is not None and storage.isStackStorage())
                stack_offset = (
                    int(storage.getStackOffset()) if is_stack else None
                )
            except Exception:  # noqa: BLE001
                continue

            if sym.isParameter():
                ordinal = 0
                try:
                    # Ghidra's getCategoryIndex gives the parameter slot for
                    # parameters, which is the ABI ordinal we want.
                    ci = sym.getCategoryIndex()
                    ordinal = int(ci) if ci is not None and ci >= 0 else 0
                except Exception:  # noqa: BLE001
                    ordinal = 0
                params.append((
                    ordinal,
                    VariableInfo(
                        name=name,
                        type=type_str,
                        stack_offset=None,
                        size=size,
                        kind="arg",
                        arg_index=ordinal,
                    ),
                ))
            else:
                locals_.append(
                    VariableInfo(
                        name=name,
                        type=type_str,
                        stack_offset=stack_offset,
                        size=size,
                        kind="stack",
                    )
                )

        # Re-index arguments by sorted ordinal so arg_index is dense ABI order.
        params.sort(key=lambda t: t[0])
        for position, (_ord, vi) in enumerate(params):
            vi.arg_index = position
            variables.append(vi)
        variables.extend(locals_)
        return variables

    @staticmethod
    def _extract_line_mappings(
        res: Any,
        code: str,
        elf_base: int,
        image_base: int,
    ) -> list[LineMapping]:
        """Best-effort line mappings from the Clang C-code markup.

        Walks the ``ClangTokenGroup`` returned by ``getCCodeMarkup()``, reading
        each token's line number (from ``getLineParent().getLineNumber()``) and
        the instruction ``Address`` attached to its ``ClangNode``'s min-address.
        Returns ``[]`` if the markup or addresses are unavailable.
        """
        try:
            markup = res.getCCodeMarkup()
        except Exception:  # noqa: BLE001
            return []
        if markup is None:
            return []

        line_to_addrs: dict[int, set[int]] = {}

        def _addr_to_file(addr: Any) -> int | None:
            try:
                if addr is None:
                    return None
                off = int(addr.getOffset())
                return (off - image_base) + elf_base
            except Exception:  # noqa: BLE001
                return None

        def _walk(node: Any) -> None:
            try:
                from ghidra.app.decompiler import ClangToken, ClangTokenGroup
            except Exception:  # noqa: BLE001
                return
            if isinstance(node, ClangTokenGroup):
                for i in range(node.numChildren()):
                    _walk(node.Child(i))
                return
            if isinstance(node, ClangToken):
                try:
                    line_parent = node.getLineParent()
                    if line_parent is None:
                        return
                    line_no = int(line_parent.getLineNumber())
                    addr = node.getMinAddress()
                    fa = _addr_to_file(addr)
                    if fa is not None:
                        line_to_addrs.setdefault(line_no, set()).add(fa)
                except Exception:  # noqa: BLE001
                    return

        try:
            _walk(markup)
        except Exception:  # noqa: BLE001
            return []

        return common.merge_line_addresses(line_to_addrs)
