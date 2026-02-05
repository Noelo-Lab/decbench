"""IDA Pro decompiler plugin."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
)

# IDA Python script for decompilation
IDA_SCRIPT = '''
import json
import sys
import idaapi
import idautils
import idc

# Get arguments
output_file = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/ida_output.json"
functions_file = idc.ARGV[2] if len(idc.ARGV) > 2 else None

def decompile_functions():
    results = {"functions": {}, "errors": []}

    # Initialize Hex-Rays
    if not idaapi.init_hexrays_plugin():
        print("Hex-Rays not available")
        return results

    # Get target functions
    if functions_file and functions_file != "all":
        with open(functions_file, "r") as f:
            target_funcs = json.load(f)
        addresses = [f["address"] for f in target_funcs]
    else:
        # Get all functions
        addresses = list(idautils.Functions())

    # Decompile each function
    for addr in addresses:
        func_name = idc.get_func_name(addr)
        if not func_name:
            continue

        try:
            cfunc = idaapi.decompile(addr)
            if cfunc:
                code = str(cfunc)

                # Normalize IDA types
                code = code.replace("__int64", "long long")
                code = code.replace("__int32", "int")
                code = code.replace("__int16", "short")
                code = code.replace("__int8", "char")
                code = code.replace("_BYTE", "char")
                code = code.replace("_WORD", "short")
                code = code.replace("_DWORD", "int")
                code = code.replace("_QWORD", "long long")

                # Extract line mappings from eamap
                line_mappings = {}
                if cfunc.get_eamap():
                    for line_num, addrs in enumerate(cfunc.get_eamap()):
                        if addrs:
                            line_mappings[line_num] = list(addrs)

                results["functions"][func_name] = {
                    "address": addr,
                    "code": code,
                    "line_count": code.count("\\n") + 1,
                    "line_mappings": line_mappings,
                    "gotos": code.count("goto "),
                    "bools": code.count(" && ") + code.count(" || "),
                }
            else:
                results["errors"].append(func_name)
        except Exception as e:
            results["errors"].append(func_name)

    return results

# Run decompilation
results = decompile_functions()

# Write results
with open(output_file, "w") as f:
    json.dump(results, f, indent=2)

# Exit IDA
idc.qexit(0)
'''


@register_decompiler("ida")
class IDADecompiler(Decompiler):
    """IDA Pro decompiler using Hex-Rays."""

    name = "ida"
    display_name = "IDA Pro"
    version = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._ida_path = self._find_ida()

    def _find_ida(self) -> Path | None:
        """Find IDA installation."""
        # Check environment variable first
        ida_env = os.environ.get("IDA_PATH")
        if ida_env:
            path = Path(ida_env)
            if path.exists():
                return path

        # Check common binary names in PATH
        for binary in ["idat64", "ida64", "idat", "ida"]:
            found = shutil.which(binary)
            if found:
                return Path(found)

        # Check common installation paths
        candidates = [
            Path("/opt/ida/idat64"),
            Path("/opt/idapro/idat64"),
            Path.home() / "ida" / "idat64",
            Path.home() / "idapro" / "idat64",
        ]

        for path in candidates:
            if path.exists():
                return path

        return None

    def is_available(self) -> bool:
        """Check if IDA is available."""
        return self._ida_path is not None

    def get_version(self) -> str | None:
        """Get IDA version."""
        if not self.is_available():
            return None

        # Version is typically in the path or could be queried
        # For now return unknown
        return "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using IDA."""
        # We let IDA discover during decompilation
        return []

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary using IDA Pro."""
        if not self.is_available():
            raise RuntimeError("IDA Pro is not available")

        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write IDA script
            script_path = tmpdir / "decompile.py"
            with open(script_path, "w") as f:
                f.write(IDA_SCRIPT)

            # Write functions file if specified
            funcs_arg = "all"
            if functions:
                funcs_path = tmpdir / "functions.json"
                with open(funcs_path, "w") as f:
                    json.dump(
                        [{"name": n, "address": a} for n, a in functions],
                        f,
                    )
                funcs_arg = str(funcs_path)

            # Output file
            output_file = tmpdir / "output.json"

            # Run IDA in batch mode
            cmd = [
                str(self._ida_path),
                "-A",  # Autonomous mode
                "-c",  # Create new database
                f"-S{script_path} {output_file} {funcs_arg}",
                "-Ohexrays:+ALL",  # Enable Hex-Rays for all
                str(binary_path),
            ]

            try:
                subprocess.run(
                    cmd,
                    timeout=self.config.binary_timeout_seconds,
                    capture_output=True,
                    check=False,  # IDA may return non-zero even on success
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
