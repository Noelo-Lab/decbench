"""Angr decompiler plugin."""

from __future__ import annotations

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


class AngrDecompilerConfig(DecompilerConfig):
    """Configuration specific to angr decompiler."""

    structurer: str = "phoenix"  # phoenix, dream, sailr
    use_deoptimizers: bool = False


@register_decompiler("angr")
class AngrDecompiler(Decompiler):
    """Angr-based decompiler using angr's decompilation engine."""

    name = "angr"
    display_name = "angr"
    version = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._angr = None
        self._project = None

        # Get angr-specific config
        if isinstance(config, AngrDecompilerConfig):
            self.structurer = config.structurer
            self.use_deoptimizers = config.use_deoptimizers
        else:
            self.structurer = (
                config.extra_options.get("structurer", "phoenix")
                if config else "phoenix"
            )
            self.use_deoptimizers = (
                config.extra_options.get("use_deoptimizers", False)
                if config else False
            )

    def is_available(self) -> bool:
        """Check if angr is available."""
        try:
            import angr
            self._angr = angr
            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        """Get angr version."""
        if self._angr is None:
            if not self.is_available():
                return None
        return self._angr.__version__

    def _get_project(self, binary_path: Path):  # type: ignore
        """Get or create an angr project for the binary."""
        if self._project is None or str(self._project.filename) != str(binary_path):
            self._project = self._angr.Project(
                str(binary_path),
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )
        return self._project

    # CRT/compiler-generated functions that are not user code
    _SKIP_NAMES = frozenset({
        "_start", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
        "_init", "_fini", "__do_global_dtors_aux", "register_tm_clones",
        "deregister_tm_clones", "frame_dummy", "__libc_start_call_main",
        "_dl_relocate_static_pie", "__gmon_start__",
    })

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using angr's CFG analysis."""
        if not self.is_available():
            return []

        project = self._get_project(binary_path)

        # Build CFG to discover functions
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
        )

        functions = []
        for addr, func in cfg.kb.functions.items():
            # Skip external/plt/alignment functions
            if func.is_simprocedure or func.is_plt:
                continue
            if getattr(func, "alignment", False):
                continue
            # Skip compiler/CRT-generated functions
            if func.name in self._SKIP_NAMES:
                continue
            functions.append((func.name, addr))

        return sorted(functions, key=lambda x: x[1])

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary using angr."""
        if not self.is_available():
            raise RuntimeError("angr is not available")

        start_time = time.time()
        project = self._get_project(binary_path)

        # Discover functions if not provided
        if functions is None:
            functions = self.discover_functions(binary_path)

        # Build CFG for decompilation
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
        )

        # Decompile each function
        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        for func_name, func_addr in functions:
            try:
                func_result = self._decompile_function(
                    project, cfg, func_name, func_addr
                )
                if func_result:
                    decompiled_functions[func_name] = func_result
                else:
                    failed_functions.append(func_name)
            except Exception as e:
                failed_functions.append(func_name)

        total_time = time.time() - start_time

        # Build result
        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.name,
                decompiler_version=self.get_version(),
                total_time_seconds=total_time,
                failed_functions=failed_functions,
                extra={"structurer": self.structurer},
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
        project,  # type: ignore
        cfg,  # type: ignore
        func_name: str,
        func_addr: int,
    ) -> FunctionDecompilation | None:
        """Decompile a single function."""
        try:
            # Get function from CFG
            if func_addr not in cfg.kb.functions:
                return None

            func = cfg.kb.functions[func_addr]

            # Decompile
            dec = project.analyses.Decompiler(
                func,
                cfg=cfg,
            )

            if dec.codegen is None:
                return None

            code = dec.codegen.text

            # Extract line mappings if available
            line_mappings = []
            if hasattr(dec.codegen, "map_addr_to_posn") and dec.codegen.map_addr_to_posn:
                addr_to_line = {}
                for addr, posn in dec.codegen.map_addr_to_posn.items():
                    if hasattr(posn, "line"):
                        line_num = posn.line
                        if line_num not in addr_to_line:
                            addr_to_line[line_num] = []
                        addr_to_line[line_num].append(addr)

                for line_num, addrs in sorted(addr_to_line.items()):
                    line_mappings.append(LineMapping(
                        line_number=line_num,
                        addresses=addrs,
                    ))

            # Count metrics from code
            metadata = self._extract_metrics(code)

            return FunctionDecompilation(
                name=func_name,
                address=func_addr,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                line_mappings=line_mappings,
                metadata=metadata,
            )

        except Exception:
            return None

    def _extract_metrics(self, code: str) -> dict[str, Any]:
        """Extract basic metrics from decompiled code."""
        return {
            "gotos": code.count("goto "),
            "bools": code.count(" && ") + code.count(" || "),
            "func_calls": (
                code.count("(") - code.count("if (") - code.count("while (")
            ),
        }

    def cleanup(self) -> None:
        """Clean up angr project."""
        self._project = None


# Variants for different structuring algorithms
@register_decompiler("angr_phoenix")
class AngrPhoenixDecompiler(AngrDecompiler):
    """Angr decompiler with Phoenix structuring algorithm."""

    name = "angr_phoenix"
    display_name = "angr (Phoenix)"

    def __init__(self, config: DecompilerConfig | None = None):
        if config is None:
            config = DecompilerConfig()
        config.extra_options["structurer"] = "phoenix"
        super().__init__(config)
        self.structurer = "phoenix"


@register_decompiler("angr_dream")
class AngrDreamDecompiler(AngrDecompiler):
    """Angr decompiler with DREAM structuring algorithm."""

    name = "angr_dream"
    display_name = "angr (DREAM)"

    def __init__(self, config: DecompilerConfig | None = None):
        if config is None:
            config = DecompilerConfig()
        config.extra_options["structurer"] = "dream"
        super().__init__(config)
        self.structurer = "dream"
