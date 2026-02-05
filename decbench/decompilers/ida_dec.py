"""IDA Pro decompiler plugin using idalib (IDA 9+)."""

from __future__ import annotations

import logging
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


@register_decompiler("ida")
class IDADecompiler(Decompiler):
    """IDA Pro decompiler using Hex-Rays via idalib (IDA 9+)."""

    name = "ida"
    display_name = "IDA Pro"
    version = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._idapro = None
        self._database_open = False

    def _find_ida(self) -> bool:
        """Check if IDA is available via idalib."""
        try:
            # IDA 9+
            import idapro
            self._idapro = idapro
            return True
        except ImportError:
            try:
                # IDA 9 Beta
                import ida as idapro
                self._idapro = idapro
                return True
            except ImportError:
                return False

    def is_available(self) -> bool:
        """Check if IDA is available."""
        return self._find_ida()

    def get_version(self) -> str | None:
        """Get IDA version."""
        if not self.is_available():
            return None

        try:
            import idaapi
            return str(idaapi.IDA_SDK_VERSION)
        except Exception:
            return "unknown"

    def _open_database(self, binary_path: Path) -> bool:
        """Open an IDA database for the binary."""
        if self._database_open:
            return True

        if self._idapro is None and not self._find_ida():
            return False

        try:
            failure = self._idapro.open_database(str(binary_path), True)
            if failure:
                _l.error("Failed to open IDA database for %s", binary_path)
                return False
            self._database_open = True
            return True
        except Exception as e:
            _l.error("Error opening IDA database: %s", e)
            return False

    def _close_database(self) -> None:
        """Close the current IDA database."""
        if not self._database_open:
            return

        try:
            self._idapro.close_database(False)
        except Exception as e:
            _l.warning("Error closing IDA database: %s", e)
        finally:
            self._database_open = False

    def _init_hexrays(self) -> bool:
        """Initialize the Hex-Rays decompiler."""
        try:
            import ida_hexrays
            return ida_hexrays.init_hexrays_plugin()
        except Exception as e:
            _l.error("Failed to initialize Hex-Rays: %s", e)
            return False

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using IDA."""
        if not self.is_available():
            return []

        if not self._open_database(binary_path):
            return []

        try:
            import idc
            import idautils

            functions = []
            for func_addr in idautils.Functions():
                func_name = idc.get_func_name(func_addr)
                if func_name:
                    functions.append((func_name, func_addr))

            return sorted(functions, key=lambda x: x[1])

        except Exception as e:
            _l.error("Failed to discover functions: %s", e)
            return []
        finally:
            self._close_database()

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary using IDA Pro via idalib."""
        if not self.is_available():
            raise RuntimeError("IDA Pro is not available")

        start_time = time.time()

        if not self._open_database(binary_path):
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

        try:
            import idc
            import idautils
            import ida_hexrays
            import ida_auto

            # Wait for auto-analysis to complete
            ida_auto.auto_wait()

            # Initialize Hex-Rays
            if not self._init_hexrays():
                _l.error("Hex-Rays decompiler not available")
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

            # Get functions to decompile
            if functions is not None:
                target_funcs = functions
            else:
                # Get all functions
                target_funcs = [
                    (idc.get_func_name(addr), addr)
                    for addr in idautils.Functions()
                    if idc.get_func_name(addr)
                ]

            # Decompile each function
            decompiled_functions: dict[str, FunctionDecompilation] = {}
            failed_functions: list[str] = []

            for func_name, func_addr in target_funcs:
                try:
                    func_result = self._decompile_function(func_name, func_addr)
                    if func_result:
                        decompiled_functions[func_name] = func_result
                    else:
                        failed_functions.append(func_name)
                except Exception as e:
                    _l.debug("Failed to decompile %s: %s", func_name, e)
                    failed_functions.append(func_name)

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
            self._close_database()

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
        func_name: str,
        func_addr: int,
    ) -> FunctionDecompilation | None:
        """Decompile a single function using Hex-Rays."""
        import idaapi
        import ida_hexrays

        try:
            cfunc = ida_hexrays.decompile(func_addr)
            if cfunc is None:
                return None

            code = str(cfunc)

            # Normalize IDA types to standard C types
            code = self._normalize_ida_types(code)

            # Extract line mappings from eamap
            line_mappings = []
            try:
                eamap = cfunc.get_eamap()
                if eamap:
                    addr_to_lines: dict[int, list[int]] = {}
                    for addr, items in eamap.items():
                        for item in items:
                            y_holder = idaapi.int_pointer()
                            if cfunc.find_item_coords(item, None, y_holder):
                                line_num = y_holder.value()
                                if line_num not in addr_to_lines:
                                    addr_to_lines[line_num] = []
                                if addr not in addr_to_lines[line_num]:
                                    addr_to_lines[line_num].append(addr)

                    for line_num, addrs in sorted(addr_to_lines.items()):
                        line_mappings.append(LineMapping(
                            line_number=line_num,
                            addresses=addrs,
                        ))
            except Exception:
                pass  # Line mapping extraction is best-effort

            # Extract metrics
            metadata = self._extract_metrics(code)

            return FunctionDecompilation(
                name=func_name,
                address=func_addr,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                line_mappings=line_mappings,
                metadata=metadata,
            )

        except ida_hexrays.DecompilationFailure:
            return None
        except Exception as e:
            _l.debug("Decompilation error for %s: %s", func_name, e)
            return None

    def _normalize_ida_types(self, code: str) -> str:
        """Normalize IDA-specific types to standard C types."""
        replacements = [
            ("__int64", "long long"),
            ("__int32", "int"),
            ("__int16", "short"),
            ("__int8", "char"),
            ("_BYTE", "char"),
            ("_WORD", "short"),
            ("_DWORD", "int"),
            ("_QWORD", "long long"),
        ]
        for old, new in replacements:
            code = code.replace(old, new)
        return code

    def _extract_metrics(self, code: str) -> dict[str, Any]:
        """Extract basic metrics from decompiled code."""
        return {
            "gotos": code.count("goto "),
            "bools": code.count(" && ") + code.count(" || "),
        }

    def cleanup(self) -> None:
        """Clean up IDA resources."""
        self._close_database()
