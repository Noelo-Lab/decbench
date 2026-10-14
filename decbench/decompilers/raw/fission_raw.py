"""Fission CLI transport. Preserve direct SSA PCs; never invent line maps."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler
from decbench.decompilers.provenance import sanitize_native_provenance
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)


@register_decompiler("fission")
class RawFissionDecompiler(Decompiler):
    name = "fission"
    display_name = "Fission"

    @staticmethod
    def _binary() -> str | None:
        value = os.environ.get("FISSION_BIN")
        return value if value and Path(value).is_file() else shutil.which("fission_cli")

    def is_available(self) -> bool:
        return self._binary() is not None

    def get_version(self) -> str | None:
        executable = self._binary()
        if not executable:
            return None
        result = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        return result.stdout.strip() or None

    @staticmethod
    def _build_function(
        record: dict[str, Any], name: str, address: int
    ) -> FunctionDecompilation | None:
        if record.get("fell_back") or record.get("error"):
            return None
        code = record.get("code_nir") or record.get("code")
        if not isinstance(code, str) or not code.strip():
            return None
        variables = [VariableInfo.model_validate(v) for v in record.get("variables", [])]
        mappings = [LineMapping.model_validate(m) for m in record.get("line_mappings_nir", [])]
        for variable in variables:
            variable.line_numbers = sorted(
                {
                    m.line_number
                    for m in mappings
                    if m.defined_variables is not None and variable.name in m.defined_variables
                }
            )
        return FunctionDecompilation(
            name=name,
            address=address,
            decompiled_code=code,
            line_count=len(code.splitlines()),
            variables=variables,
            line_mappings=mappings,
            metadata={
                **common.extract_metrics(code),
                "provenance_source": "fission_scalar_ssa",
                "provenance_granularity": "variable_def_use_and_scoped_definition_lines",
                "code_layer": "nir",
            },
        )

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        executable = self._binary()
        if not executable:
            raise RuntimeError("Fission CLI unavailable; set FISSION_BIN")
        if self.config.extra_options:
            raise ValueError(
                "Fission options use FISSION_RESOURCE_ROOT / FISSION_WORKING_DIR; "
                "unknown extra_options"
            )
        binary_path = binary_path.resolve()
        start = time.monotonic()
        selected = {int(address): name for name, address in functions or []}
        requested = set(selected) | common.addr_targets_of(function_names)
        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            output_dir=output_dir,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                extra={"backend": "fission", "via": "raw"},
            ),
        )
        with tempfile.TemporaryDirectory(prefix="decbench-fission-") as directory:
            command = [executable]
            if root := os.environ.get("FISSION_RESOURCE_ROOT"):
                command += ["--resource-root", root]
            command += [
                "decomp",
                str(binary_path),
                "--json",
                "--no-db",
                "--layer",
                "nir",
                "--no-header",
                "--no-warnings",
                "--timeout-ms",
                str(int(self.config.function_timeout_seconds * 1000)),
            ]
            if functions is not None and not functions:
                return result
            if requested:
                address_file = Path(directory) / "addresses.txt"
                address_file.write_text("".join(f"0x{a:x}\n" for a in sorted(requested)))
                command += ["--addresses-file", str(address_file)]
            else:
                command += ["--all"]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.environ.get("FISSION_WORKING_DIR"),
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=self.config.binary_timeout_seconds)
            except subprocess.TimeoutExpired:
                result.decompiler.timeout_occurred = True
                result.decompiler.extra["error"] = "binary timeout; no completed JSON payload"
                stdout = ""
            finally:
                if process.poll() is None:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=15)
            if stdout:
                payload = json.loads(stdout)
                records = (
                    payload.get("functions", [payload]) if isinstance(payload, dict) else payload
                )
                seen = set()
                for record in records:
                    raw = record.get("address")
                    address = int(raw, 0) if isinstance(raw, str) else int(raw)
                    if address in seen:
                        raise ValueError("ambiguous duplicate Fission function address")
                    seen.add(address)
                    if requested and address not in requested:
                        continue
                    name = selected.get(address, str(record.get("name") or f"sub_{address:x}"))
                    function = self._build_function(record, name, address)
                    if function is None:
                        key = result.add_function(
                            FunctionDecompilation(name=name, address=address, decompiled_code="")
                        )
                        result.decompiler.failed_functions.append(key)
                    else:
                        result.add_function(function)
                if process.returncode:
                    result.decompiler.extra["process_exit_code"] = process.returncode
                    result.decompiler.extra["stderr_tail"] = stderr[-1000:]
            returned = {f.address for f in result.functions.values()}
            for address in sorted(requested - returned):
                key = result.add_function(
                    FunctionDecompilation(
                        name=selected.get(address, f"sub_{address:x}"),
                        address=address,
                        decompiled_code="",
                    )
                )
                result.decompiler.failed_functions.append(key)
            observed = {f.address for f in result.functions.values() if f.decompiled_code.strip()}
            result.decompiler.extra["requested_addresses"] = sorted(requested)
            result.decompiler.extra["missing_requested_addresses"] = sorted(requested - observed)
            result.decompiler.total_time_seconds = time.monotonic() - start
        # Worker inputs are isolated/stripped: defer until the evaluator owns
        # exact debug ranges. Final metrics still validate strictly.
        sanitize_native_provenance(result, defer_unavailable=True)
        if progress_path:
            common.dump_progress(progress_path, result)
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"fission_{binary_path.stem}.c")
        return result
