"""Ghidra decompiler plugin."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
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

# Ghidra script to decompile functions
GHIDRA_SCRIPT = '''
# Ghidra Python script for decompilation
# @category DecBench

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def main():
    output_file = askString("Output", "Output file path")
    functions_file = askString("Functions", "Functions file path (optional)")

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    monitor = ConsoleTaskMonitor()
    results = {"functions": {}, "errors": []}

    # Get functions to decompile
    if functions_file and functions_file != "all":
        with open(functions_file, "r") as f:
            target_funcs = json.load(f)
        func_manager = currentProgram.getFunctionManager()
        functions = []
        for func_data in target_funcs:
            addr = currentProgram.getAddressFactory().getAddress(hex(func_data["address"]))
            func = func_manager.getFunctionAt(addr)
            if func:
                functions.append(func)
    else:
        functions = list(currentProgram.getFunctionManager().getFunctions(True))

    # Decompile each function
    for func in functions:
        try:
            dec_result = decompiler.decompileFunction(func, 600, monitor)
            if dec_result and dec_result.decompileCompleted():
                decomp_func = dec_result.getDecompiledFunction()
                if decomp_func:
                    code = decomp_func.getC()

                    # Extract line mappings
                    line_mappings = {}
                    high_func = dec_result.getHighFunction()
                    if high_func:
                        for block in high_func.getBasicBlocks():
                            for pcode in block.getIterator():
                                seq = pcode.getSeqnum()
                                if seq:
                                    addr = seq.getTarget().getOffset()
                                    line = pcode.getLineNumber()
                                    if line > 0:
                                        if line not in line_mappings:
                                            line_mappings[line] = []
                                        if addr not in line_mappings[line]:
                                            line_mappings[line].append(addr)

                    results["functions"][func.getName()] = {
                        "address": func.getEntryPoint().getOffset(),
                        "code": code,
                        "line_count": code.count("\\n") + 1,
                        "line_mappings": line_mappings,
                        "gotos": code.count("goto "),
                        "bools": code.count(" && ") + code.count(" || "),
                    }
            else:
                results["errors"].append(func.getName())
        except Exception as e:
            results["errors"].append(func.getName())

    decompiler.dispose()

    # Write results
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

main()
'''


@register_decompiler("ghidra")
class GhidraDecompiler(Decompiler):
    """Ghidra-based decompiler."""

    name = "ghidra"
    display_name = "Ghidra"
    version = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._ghidra_path = self._find_ghidra()

    def _find_ghidra(self) -> Path | None:
        """Find Ghidra installation."""
        # Check common locations
        candidates = [
            Path("/opt/ghidra/support/analyzeHeadless"),
            Path("/usr/local/share/ghidra/support/analyzeHeadless"),
            Path.home() / "ghidra" / "support" / "analyzeHeadless",
        ]

        # Check PATH
        ghidra_in_path = shutil.which("analyzeHeadless")
        if ghidra_in_path:
            candidates.insert(0, Path(ghidra_in_path))

        # Check environment variable
        import os
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home:
            candidates.insert(0, Path(ghidra_home) / "support" / "analyzeHeadless")

        for path in candidates:
            if path.exists():
                return path

        return None

    def is_available(self) -> bool:
        """Check if Ghidra is available."""
        return self._ghidra_path is not None

    def get_version(self) -> str | None:
        """Get Ghidra version."""
        if not self.is_available():
            return None

        try:
            # Try to get version from Ghidra installation
            version_file = self._ghidra_path.parent.parent / "Ghidra" / "application.properties"
            if version_file.exists():
                with open(version_file) as f:
                    for line in f:
                        if line.startswith("application.version="):
                            return line.split("=")[1].strip()
        except Exception:
            pass

        return "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using Ghidra."""
        # We'll let Ghidra discover functions during decompilation
        # This is a placeholder that could be enhanced
        return []

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary using Ghidra."""
        if not self.is_available():
            raise RuntimeError("Ghidra is not available")

        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write Ghidra script
            script_path = tmpdir / "decompile.py"
            with open(script_path, "w") as f:
                f.write(GHIDRA_SCRIPT)

            # Write functions file if specified
            funcs_file = "all"
            if functions:
                funcs_path = tmpdir / "functions.json"
                with open(funcs_path, "w") as f:
                    json.dump(
                        [{"name": n, "address": a} for n, a in functions],
                        f,
                    )
                funcs_file = str(funcs_path)

            # Output file
            output_file = tmpdir / "output.json"

            # Create temporary Ghidra project
            project_dir = tmpdir / "ghidra_project"
            project_dir.mkdir()

            # Run Ghidra headless
            cmd = [
                str(self._ghidra_path),
                str(project_dir),
                "decbench_project",
                "-import", str(binary_path),
                "-scriptPath", str(tmpdir),
                "-postScript", "decompile.py",
                str(output_file),
                funcs_file,
                "-deleteProject",
            ]

            try:
                subprocess.run(
                    cmd,
                    timeout=self.config.binary_timeout_seconds,
                    capture_output=True,
                    check=True,
                )
            except subprocess.TimeoutExpired:
                return DecompilationResult(
                    binary_path=binary_path,
                    binary_name=binary_path.stem,
                    decompiler=DecompilerMetadata(
                        decompiler_name=self.name,
                        decompiler_version=self.get_version(),
                        total_time_seconds=time.time() - start_time,
                        timeout_occurred=True,
                    ),
                )
            except subprocess.CalledProcessError:
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

            # Parse results
            if not output_file.exists():
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

            with open(output_file) as f:
                data = json.load(f)

        total_time = time.time() - start_time

        # Convert to our models
        decompiled_functions: dict[str, FunctionDecompilation] = {}

        for func_name, func_data in data.get("functions", {}).items():
            line_mappings = []
            for line_str, addrs in func_data.get("line_mappings", {}).items():
                line_mappings.append(LineMapping(
                    line_number=int(line_str),
                    addresses=addrs,
                ))

            decompiled_functions[func_name] = FunctionDecompilation(
                name=func_name,
                address=func_data["address"],
                decompiled_code=func_data["code"],
                line_count=func_data.get("line_count", 0),
                line_mappings=line_mappings,
                metadata={
                    "gotos": func_data.get("gotos", 0),
                    "bools": func_data.get("bools", 0),
                },
            )

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.name,
                decompiler_version=self.get_version(),
                total_time_seconds=total_time,
                failed_functions=data.get("errors", []),
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
