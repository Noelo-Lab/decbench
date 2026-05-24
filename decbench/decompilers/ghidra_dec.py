"""Ghidra decompiler plugin using pyghidra."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
)

_l = logging.getLogger(__name__)


@register_decompiler("ghidra")
class GhidraDecompiler(Decompiler):
    """Ghidra-based decompiler using pyghidra for headless operation."""

    name = "ghidra"
    display_name = "Ghidra"
    version = None

    # CRT/compiler-generated functions that are not user code
    _SKIP_NAMES = frozenset({
        "_start", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
        "_init", "_fini", "__do_global_dtors_aux", "register_tm_clones",
        "deregister_tm_clones", "frame_dummy", "__libc_start_call_main",
        "_dl_relocate_static_pie", "__gmon_start__",
    })

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._pyghidra = None
        self._launcher_started = False
        self._flat_api = None
        self._project = None
        self._program = None

    def _check_ghidra_install(self) -> bool:
        """Check if GHIDRA_INSTALL_DIR is set."""
        return os.environ.get("GHIDRA_INSTALL_DIR") is not None

    def is_available(self) -> bool:
        """Check if pyghidra and Ghidra are available."""
        if not self._check_ghidra_install():
            _l.warning("GHIDRA_INSTALL_DIR environment variable not set")
            return False

        try:
            import pyghidra
            self._pyghidra = pyghidra
            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        """Get Ghidra version."""
        if not self.is_available():
            return None

        try:
            # Try to get version from Ghidra installation
            ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
            if ghidra_home:
                version_file = Path(ghidra_home) / "Ghidra" / "application.properties"
                if version_file.exists():
                    with open(version_file) as f:
                        for line in f:
                            if line.startswith("application.version="):
                                return line.split("=")[1].strip()
        except Exception:
            pass

        return "unknown"

    def _start_headless(self) -> None:
        """Start the pyghidra headless launcher if not already started."""
        if self._launcher_started:
            return

        from pyghidra.launcher import PyGhidraLauncher, HeadlessPyGhidraLauncher

        if not PyGhidraLauncher.has_launched():
            HeadlessPyGhidraLauncher().start()

        self._launcher_started = True

    def _open_program(
        self,
        binary_path: Path,
        analyze: bool = True,
    ) -> tuple[Any, Any, Any]:
        """
        Open a program in Ghidra headless mode.

        Returns:
            Tuple of (flat_api, project, program)
        """
        self._start_headless()

        from pyghidra.core import _analyze_program
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.base.project import GhidraProject
        from java.io import IOException
        from ghidra.util.exception import NotFoundException

        # Set up project location
        project_location = binary_path.parent / f"{binary_path.name}_ghidra"
        project_name = f"{binary_path.name}_project"
        project_location.mkdir(exist_ok=True, parents=True)

        # Open or create project
        program = None
        try:
            project = GhidraProject.openProject(project_location, project_name, True)
            # Check if program already exists
            if project.getRootFolder().getFile(binary_path.name):
                program = project.openProgram("/", binary_path.name, False)
        except (IOException, NotFoundException):
            project = GhidraProject.createProject(project_location, project_name, False)

        # Import program if not already loaded
        if program is None:
            program = project.importProgram(binary_path)
            if program is None:
                raise RuntimeError(f"Ghidra failed to import '{binary_path}'")
            project.saveAs(program, "/", program.getName(), True)

        GhidraScriptUtil.acquireBundleHostReference()
        flat_api = FlatProgramAPI(program)

        if analyze:
            _analyze_program(flat_api, program)

        return flat_api, project, program

    def _close_program(self) -> None:
        """Close the current program and project."""
        if self._program is None or self._project is None:
            return

        try:
            from ghidra.app.script import GhidraScriptUtil
            GhidraScriptUtil.releaseBundleHostReference()
            self._project.save(self._program)
            self._project.close()
        except Exception as e:
            _l.warning("Failed to close Ghidra project: %s", e)
        finally:
            self._flat_api = None
            self._project = None
            self._program = None

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using Ghidra."""
        if not self.is_available():
            return []

        try:
            flat_api, project, program = self._open_program(binary_path, analyze=True)
            self._flat_api = flat_api
            self._project = project
            self._program = program

            functions = []
            func_manager = program.getFunctionManager()
            for func in func_manager.getFunctions(True):
                if func.isExternal() or func.isThunk():
                    continue
                name = str(func.getName())
                if name in self._SKIP_NAMES:
                    continue
                addr = int(func.getEntryPoint().getOffset())
                functions.append((name, addr))

            return sorted(functions, key=lambda x: x[1])

        except Exception as e:
            _l.error("Failed to discover functions: %s", e)
            return []

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary using Ghidra via pyghidra."""
        if not self.is_available():
            raise RuntimeError("Ghidra/pyghidra is not available")

        start_time = time.time()

        try:
            # Open the binary
            flat_api, project, program = self._open_program(binary_path, analyze=True)
            self._flat_api = flat_api
            self._project = project
            self._program = program

            # Initialize decompiler
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            decompiler = DecompInterface()
            decompiler.openProgram(program)
            monitor = ConsoleTaskMonitor()

            # Get functions to decompile
            func_manager = program.getFunctionManager()
            if functions is not None:
                # Map provided functions to Ghidra functions
                target_funcs = []
                addr_factory = program.getAddressFactory()
                for func_name, func_addr in functions:
                    addr = addr_factory.getAddress(hex(func_addr))
                    func = func_manager.getFunctionAt(addr)
                    if func:
                        target_funcs.append(func)
            else:
                # Get all non-external, non-stub functions
                target_funcs = [
                    func for func in func_manager.getFunctions(True)
                    if not func.isExternal()
                    and not func.isThunk()
                    and str(func.getName()) not in self._SKIP_NAMES
                ]

            # Decompile each function
            decompiled_functions: dict[str, FunctionDecompilation] = {}
            failed_functions: list[str] = []

            for func in target_funcs:
                func_name = str(func.getName())
                try:
                    func_result = self._decompile_function(
                        decompiler, func, monitor
                    )
                    if func_result:
                        decompiled_functions[func_name] = func_result
                    else:
                        failed_functions.append(func_name)
                except Exception as e:
                    _l.debug("Failed to decompile %s: %s", func_name, e)
                    failed_functions.append(func_name)

            decompiler.dispose()

        except Exception as e:
            _l.error("Decompilation failed: %s", e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.name,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                ),
            )
        finally:
            self._close_program()

        total_time = time.time() - start_time

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.name,
                decompiler_version=self.get_version(),
                total_time_seconds=total_time,
                failed_functions=failed_functions,
            ),
            functions=decompiled_functions,
            output_dir=output_dir,
        )

        # Write output files if output_dir specified
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            c_file = output_dir / f"{self.name}_{binary_path.stem}.c"
            result.to_c_file(c_file)
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    def _decompile_function(
        self,
        decompiler: Any,
        func: Any,
        monitor: Any,
    ) -> FunctionDecompilation | None:
        """Decompile a single function using Ghidra's DecompInterface."""
        dec_result = decompiler.decompileFunction(func, 600, monitor)

        if not dec_result or not dec_result.decompileCompleted():
            return None

        decomp_func = dec_result.getDecompiledFunction()
        if not decomp_func:
            return None

        code = str(decomp_func.getC())

        # Extract line mappings from high function
        line_mappings = []
        high_func = dec_result.getHighFunction()
        if high_func:
            addr_to_line: dict[int, list[int]] = {}
            try:
                for block in high_func.getBasicBlocks():
                    for pcode in block.getIterator():
                        seq = pcode.getSeqnum()
                        if seq:
                            addr = int(seq.getTarget().getOffset())
                            line = pcode.getLineNumber()
                            if line > 0:
                                if line not in addr_to_line:
                                    addr_to_line[line] = []
                                if addr not in addr_to_line[line]:
                                    addr_to_line[line].append(addr)
            except Exception:
                pass  # Line mapping extraction is best-effort

            for line_num, addrs in sorted(addr_to_line.items()):
                line_mappings.append(LineMapping(
                    line_number=line_num,
                    addresses=addrs,
                ))

        # Extract metrics
        metadata = self._extract_metrics(code)

        return FunctionDecompilation(
            name=str(func.getName()),
            address=int(func.getEntryPoint().getOffset()),
            decompiled_code=code,
            line_count=code.count("\n") + 1,
            line_mappings=line_mappings,
            metadata=metadata,
        )

    def _extract_metrics(self, code: str) -> dict[str, Any]:
        """Extract basic metrics from decompiled code."""
        return {
            "gotos": code.count("goto "),
            "bools": code.count(" && ") + code.count(" || "),
        }

    def cleanup(self) -> None:
        """Clean up Ghidra resources."""
        self._close_program()
