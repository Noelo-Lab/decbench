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
supplies an ``install_dir`` (set into ``GHIDRA_INSTALL_DIR`` before the JVM
starts) and optionally a ``java_home``, so ``ghidra@10.4`` vs ``ghidra@12.1``
launch different installs on the right JDK. Installs older than 12.0 are
launched via the predecessor ``pyhidra`` package (pip ``pyghidra`` 3.x refuses
anything < 12.0); the two expose the same API surface.

Note: the launcher boots a single JVM per process and cannot switch installs
afterwards, so each *process* handles one Ghidra version / binary.
The run driver already spawns a fresh process per decompile task.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
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

    def _settings(self) -> dict:
        """Per-version settings from ``decompilers.toml`` (may be empty)."""
        from decbench.decompilers.spec import version_settings

        return version_settings("ghidra", self.requested_version)

    def _install_dir(self) -> str | None:
        """Resolve which Ghidra install to launch.

        Prefers the per-version config (``decompilers.toml``), falls back to
        ``GHIDRA_INSTALL_DIR``.
        """
        install = self._settings().get("install_dir")
        if install:
            return str(install)
        return os.environ.get("GHIDRA_INSTALL_DIR")

    def _version_tuple(self) -> tuple[int, ...] | None:
        """The resolved install's (major, minor) version, or None if unreadable."""
        version = self.get_version()
        try:
            return tuple(int(part) for part in str(version).split(".")[:2])
        except (TypeError, ValueError):
            return None

    def _launcher(self) -> Any:
        """The launcher module matching the resolved install's version.

        pip ``pyghidra`` (3.x) refuses to launch Ghidra < 12.0, and no pip
        release of it ever supported < 11.2, so historical installs need a
        version-matched launcher:

        * ``>= 12.0`` — the pip ``pyghidra`` in the venv.
        * ``11.2 .. 11.x`` — the install's own bundled PyGhidra
          (``Ghidra/Features/PyGhidra/pypkg/src``), imported ahead of the pip
          one. (``pyhidra`` nominally launches these too, but its project
          handling breaks on 11.4: "Project marker file not found".)
        * ``< 11.2`` — the predecessor package ``pyhidra`` (same project
          pre-rename; identical ``start``/``started``/``open_program``).

        All bind ONE JVM per process, which the per-task subprocess model
        already accommodates.
        """
        version = self._version_tuple()
        if version is None or version >= (12,):
            import pyghidra

            return pyghidra
        if version >= (11, 2):
            bundled = Path(self._install_dir() or "") / "Ghidra/Features/PyGhidra/pypkg/src"
            if bundled.is_dir():
                import sys

                if "pyghidra" in sys.modules:
                    loaded = getattr(sys.modules["pyghidra"], "__file__", "") or ""
                    if not loaded.startswith(str(bundled)):
                        raise RuntimeError(
                            "pip pyghidra already imported in this process; a "
                            f"Ghidra {version} install needs its bundled PyGhidra "
                            "and must run in a fresh process"
                        )
                elif str(bundled) not in sys.path:
                    sys.path.insert(0, str(bundled))
                import pyghidra

                return pyghidra
        import pyhidra

        return pyhidra

    def _ensure_started(self) -> Any:
        """Point ``GHIDRA_INSTALL_DIR`` at the resolved install, then start JVM.

        Honours a per-version ``java_home`` from ``decompilers.toml`` (older
        Ghidra lines need older JDKs: <= 11.1 wants JDK 17, >= 11.2 wants 21),
        exported before the JVM boots so JPype picks the right libjvm.

        Forces Java AWT headless mode: when ``DISPLAY`` is set but no usable X
        server is reachable, ``GhidraProject.createProject`` otherwise dies with
        an ``AWTError``. Setting ``-Djava.awt.headless=true`` (and clearing
        ``DISPLAY``) makes Ghidra run headless regardless of the environment.

        Returns the launcher module (``pyghidra`` or ``pyhidra``) so callers
        use the same module they were started with.
        """
        install = self._install_dir()
        if install:
            os.environ["GHIDRA_INSTALL_DIR"] = install

        java_home = self._settings().get("java_home")
        if java_home:
            os.environ["JAVA_HOME"] = str(java_home)
            os.environ["PATH"] = (
                str(Path(java_home) / "bin") + os.pathsep + os.environ.get("PATH", "")
            )

        opts = os.environ.get("_JAVA_OPTIONS", "")
        if "java.awt.headless" not in opts:
            os.environ["_JAVA_OPTIONS"] = (opts + " -Djava.awt.headless=true").strip()
        # A stale DISPLAY triggers the AWT error even in headless Ghidra.
        os.environ.pop("DISPLAY", None)

        launcher = self._launcher()
        if not launcher.started():
            launcher.start()
        return launcher

    @contextlib.contextmanager
    def _open_program(self, launcher: Any, binary_path: Path) -> Any:
        """``open_program`` with an isolated, throwaway Ghidra project.

        The launcher's default project location is the BINARY's own directory
        (``<binary>_ghidra``), which (a) litters the results tree and (b) is
        shared state: two processes analyzing the same binary — exactly what a
        multi-version run does — race on the project files and die with
        ``Failed to overwrite existing project file`` / ``File error during
        save``. A per-process temp dir removes both problems.
        """
        project_dir = Path(tempfile.mkdtemp(prefix="decbench_ghidra_"))
        try:
            with launcher.open_program(
                str(binary_path),
                project_location=str(project_dir),
                project_name=f"{binary_path.name}_decbench",
                analyze=True,
            ) as flat:
                yield flat
        finally:
            shutil.rmtree(project_dir, ignore_errors=True)

    def is_available(self) -> bool:
        if self._install_dir() is None:
            return False
        try:
            self._launcher()
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

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary with Ghidra natively (one program/JVM per process)."""
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        code_ranges = common.executable_code_ranges(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "ghidra", "via": "raw"}
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
            launcher = self._ensure_started()
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            with self._open_program(launcher, binary_path) as flat:
                program = flat.getCurrentProgram()
                image_base = int(program.getImageBase().getOffset())

                requested = {n for (n, _a) in functions} if functions is not None else None

                enumerated = self._enumerate(program, elf_base, code_ranges)
                if requested is not None:
                    enumerated = [(n, a) for (n, a) in enumerated if n in requested]

                enumerated = common.narrow_to_source(
                    enumerated,
                    function_names,
                    backend="ghidra",
                    binary_name=binary_path.name,
                )

                ifc = DecompInterface()
                ifc.openProgram(program)
                monitor = ConsoleTaskMonitor()
                timeout_s = int(self.config.function_timeout_seconds)
                by_name = self._functions_by_name(program)

                for func_name, file_addr in enumerated:
                    func_result = None
                    g_func = by_name.get(func_name)
                    if g_func is not None:
                        try:
                            func_result = self._decompile_one(
                                ifc,
                                g_func,
                                func_name,
                                file_addr,
                                elf_base,
                                image_base,
                                timeout_s,
                                monitor,
                            )
                        except Exception as e:  # noqa: BLE001
                            _l.debug(
                                "ghidra-raw: failed to decompile %s: %s",
                                func_name,
                                e,
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

    def _enumerate(
        self,
        program: Any,
        elf_base: int,
        code_ranges: common.CodeRangeFilter,
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
            if common.should_skip_function(name, file_addr, code_ranges):
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
        variables, symbol_indices = self._extract_variables_with_symbols(high)
        try:
            function_body = g_func.getBody()
        except Exception:  # noqa: BLE001
            function_body = None
        line_mappings, variable_lines = self._extract_markup_evidence(
            res,
            high,
            symbol_indices,
            elf_base,
            image_base,
            code=code,
            function_body=function_body,
        )
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
    def _extract_variables(high: Any) -> list[VariableInfo]:
        variables, _symbol_indices = RawGhidraDecompiler._extract_variables_with_symbols(high)
        return variables

    @staticmethod
    def _extract_variables_with_symbols(
        high: Any,
    ) -> tuple[list[VariableInfo], dict[int, int]]:
        """Pull arguments (ABI order) and stack locals from the HighFunction.

        Parameters are emitted first (ordered by their parameter ordinal, so
        ``arg_index`` matches DWARF's formal-parameter order); the rest become
        stack/locals. The returned symbol-id map connects Clang variable tokens
        back to their ``VariableInfo`` entry.
        """
        variables: list[VariableInfo] = []
        symbol_indices: dict[int, int] = {}
        if high is None:
            return variables, symbol_indices
        try:
            lsm = high.getLocalSymbolMap()
        except Exception:  # noqa: BLE001
            return variables, symbol_indices
        if lsm is None:
            return variables, symbol_indices

        params: list[tuple[int, int, VariableInfo]] = []
        locals_: list[tuple[int, VariableInfo]] = []

        syms = lsm.getSymbols()
        while syms.hasNext():
            sym = syms.next()
            try:
                symbol_id = int(sym.getId())
                name = str(sym.getName() or "")
                dtype = sym.getDataType()
                type_str = str(dtype.getDisplayName()) if dtype is not None else ""
                size = int(sym.getSize()) if sym.getSize() is not None else None
                storage = sym.getStorage()
                is_stack = bool(storage is not None and storage.isStackStorage())
                stack_offset = int(storage.getStackOffset()) if is_stack else None
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
                params.append(
                    (
                        ordinal,
                        symbol_id,
                        VariableInfo(
                            name=name,
                            type=type_str,
                            stack_offset=None,
                            size=size,
                            kind="arg",
                            arg_index=ordinal,
                        ),
                    )
                )
            else:
                locals_.append(
                    (
                        symbol_id,
                        VariableInfo(
                            name=name,
                            type=type_str,
                            stack_offset=stack_offset,
                            size=size,
                            kind="stack",
                        ),
                    )
                )

        params.sort(key=lambda t: t[0])
        for position, (_ord, symbol_id, vi) in enumerate(params):
            vi.arg_index = position
            symbol_indices[symbol_id] = len(variables)
            variables.append(vi)
        for symbol_id, vi in locals_:
            symbol_indices[symbol_id] = len(variables)
            variables.append(vi)
        return variables, symbol_indices

    @staticmethod
    def _extract_line_mappings(
        res: Any,
        code: str,
        elf_base: int,
        image_base: int,
    ) -> list[LineMapping]:
        line_mappings, _variable_lines = RawGhidraDecompiler._extract_markup_evidence(
            res,
            None,
            {},
            elf_base,
            image_base,
        )
        return line_mappings

    @staticmethod
    def _extract_markup_evidence(
        res: Any,
        high: Any,
        symbol_indices: dict[int, int],
        elf_base: int,
        image_base: int,
        *,
        code: str | None = None,
        function_body: Any = None,
    ) -> tuple[list[LineMapping], dict[int, set[int]]]:
        try:
            markup = res.getCCodeMarkup()
        except Exception:  # noqa: BLE001
            return [], {}
        if markup is None:
            return [], {}

        line_to_addrs: dict[int, set[int]] = {}
        variable_lines: dict[int, set[int]] = {}
        line_count = code.count("\n") + 1 if code is not None else None

        def _addr_to_file(addr: Any) -> int | None:
            try:
                if addr is None:
                    return None
                get_address_space = getattr(addr, "getAddressSpace", None)
                if callable(get_address_space):
                    address_space = get_address_space()
                    if address_space is not None and not bool(address_space.isMemorySpace()):
                        return None
                if function_body is not None and not bool(function_body.contains(addr)):
                    return None
                off = int(addr.getOffset())
                if off < image_base:
                    return None
                file_addr = (off - image_base) + elf_base
                return file_addr if file_addr >= elf_base else None
            except Exception:  # noqa: BLE001
                return None

        def _walk(node: Any) -> None:
            try:
                child_count = int(node.numChildren())
            except Exception:  # noqa: BLE001
                return
            if child_count:
                for i in range(child_count):
                    try:
                        _walk(node.Child(i))
                    except Exception:  # noqa: BLE001
                        continue
                return
            try:
                line_parent = node.getLineParent()
                if line_parent is None:
                    return
                line_no = int(line_parent.getLineNumber())
                if line_no <= 0 or (line_count is not None and line_no > line_count):
                    return
                for address_getter in ("getMinAddress", "getMaxAddress"):
                    getter = getattr(node, address_getter, None)
                    fa = _addr_to_file(getter()) if callable(getter) else None
                    if fa is not None:
                        line_to_addrs.setdefault(line_no, set()).add(fa)
                if high is None or not bool(node.isVariableRef()):
                    return
                symbol = node.getHighSymbol(high)
                if symbol is None:
                    return
                index = symbol_indices.get(int(symbol.getId()))
                if index is not None:
                    variable_lines.setdefault(index, set()).add(line_no)
            except Exception:  # noqa: BLE001
                return

        try:
            _walk(markup)
        except Exception:  # noqa: BLE001
            return [], {}

        return common.merge_line_addresses(line_to_addrs), variable_lines
