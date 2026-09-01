"""Decompiler plugins backed by the declib library.

All decompiler backends (IDA Pro, Ghidra, Binary Ninja, angr) are accessed
through declib's unified ``DecompilerInterface``, which handles headless
project management, decompilation, and artifact (variable/type) extraction.

Notes:
    - declib returns "lifted" addresses (rebased so the binary's first
      segment starts at 0). DecBench stores addresses in the binary's linked
      address space (the same space DWARF uses). ELF uses its lowest PT_LOAD
      address; PE uses the backend's canonical ImageBase-or-section origin.
    - ``DecompilerConfig.function_timeout_seconds`` is advisory only:
      declib does not expose per-function decompilation timeouts.
"""

from __future__ import annotations

import logging
import os
import struct
import time
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common as raw_common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
    VariableOccurrencePolicy,
    with_variable_occurrence_policy,
)
from decbench.utils import binfmt

if TYPE_CHECKING:
    from declib.api import DecompilerInterface

_l = logging.getLogger(__name__)


def _address_matches(address: int, targets: set[int]) -> bool:
    return address in targets or (address & ~1) in targets or (address | 1) in targets


def _pe_file_space_origins(binary_path: Path, image_base: int) -> frozenset[int]:
    """Return canonical PE addresses a fresh backend may use as its lifted zero."""
    try:
        with binary_path.open("rb") as stream:
            header = stream.read(0x40)
            if len(header) != 0x40 or header[:2] != b"MZ":
                raise ValueError("missing DOS header")

            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            stream.seek(pe_offset)
            if stream.read(4) != b"PE\x00\x00":
                raise ValueError("missing PE signature")

            coff_header = stream.read(20)
            if len(coff_header) != 20:
                raise ValueError("truncated COFF header")
            section_count = struct.unpack_from("<H", coff_header, 2)[0]
            optional_size = struct.unpack_from("<H", coff_header, 16)[0]
            optional_header = stream.read(optional_size)
            if len(optional_header) != optional_size:
                raise ValueError("truncated optional header")

            magic = struct.unpack_from("<H", optional_header, 0)[0]
            if magic == 0x10B:
                image_base_offset, image_base_size = 28, 4
            elif magic == 0x20B:
                image_base_offset, image_base_size = 24, 8
            else:
                raise ValueError(f"unsupported optional-header magic {magic:#x}")
            if len(optional_header) < image_base_offset + image_base_size:
                raise ValueError("optional header has no ImageBase")

            encoded_image_base = int.from_bytes(
                optional_header[image_base_offset : image_base_offset + image_base_size],
                "little",
            )
            if encoded_image_base != image_base:
                raise ValueError(
                    f"header ImageBase {encoded_image_base:#x} does not match {image_base:#x}"
                )

            origins = {image_base}
            for _ in range(section_count):
                section_header = stream.read(40)
                if len(section_header) != 40:
                    raise ValueError("truncated section table")
                virtual_size, virtual_address, raw_size = struct.unpack_from(
                    "<III", section_header, 8
                )
                if virtual_size or raw_size:
                    origins.add(image_base + virtual_address)
    except (OSError, struct.error, ValueError) as e:
        raise ValueError(f"could not validate PE file-space origins: {e}") from e
    return frozenset(origins)


class DeclibDecompiler(Decompiler):
    """Base class for decompilers driven through declib's DecompilerInterface."""

    name = "declib"
    display_name = "declib"
    force_decompiler: str = ""
    _uses_project_dir: bool = False
    _line_map_style: str | None = None

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    def is_available(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def get_version(self) -> str | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary through declib.

        Args:
            function_names: If given, only functions whose ELF-file-space
                address or legacy name is in this set are decompiled. An
                explicit filter is fail-closed; an empty/None set means all
                enumerated functions.
            progress_path: If given, the partial result is pickled here after
                each function so a hard external timeout-kill still preserves the
                functions decompiled so far (important for slow backends like
                angr on large binaries).
        """
        import pickle as _pickle

        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        header_base = raw_common.elf_min_vaddr(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        deci = None
        try:
            deci = self._make_deci(binary_path, self._project_dir_for(binary_path, output_dir))
            file_base = self._file_space_base(deci, binary_path, header_base)

            if functions is not None:
                target_funcs = [(name, addr - file_base) for name, addr in functions]
            else:
                target_funcs = self._enumerate_functions(
                    deci,
                    binary_path,
                    file_base,
                    raw_common.addr_targets_of(function_names),
                )

            if function_names:
                address_targets = {
                    int(value)
                    for value in function_names
                    if isinstance(value, int) and not isinstance(value, bool)
                }
                name_targets = {value for value in function_names if isinstance(value, str)}
                filtered = [
                    (name, lifted_addr)
                    for name, lifted_addr in target_funcs
                    if name in name_targets
                    or _address_matches(lifted_addr + file_base, address_targets)
                ]
                if filtered:
                    _l.debug(
                        "declib/%s: filtered %d/%d functions to source set for %s",
                        self.name,
                        len(filtered),
                        len(target_funcs),
                        binary_path.name,
                    )
                else:
                    _l.warning(
                        "declib/%s: no function matched the requested source set for %s",
                        self.name,
                        binary_path.name,
                    )
                target_funcs = filtered

            def _dump_progress() -> None:
                if progress_path is None:
                    return
                try:
                    partial = DecompilationResult(
                        binary_path=binary_path,
                        binary_name=binary_path.stem,
                        decompiler=DecompilerMetadata(
                            decompiler_name=self.name,
                            decompiler_version=self.get_version(),
                            total_time_seconds=time.time() - start_time,
                            failed_functions=list(failed_functions),
                            extra={
                                "backend": self.force_decompiler,
                                "via": "declib",
                                "partial": True,
                            },
                        ),
                        functions=dict(decompiled_functions),
                        output_dir=output_dir,
                    )
                    tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
                    tmp.write_bytes(_pickle.dumps(partial))
                    tmp.replace(progress_path)
                except Exception:  # noqa: BLE001 - progress dump is best-effort
                    pass

            for func_name, lifted_addr in target_funcs:
                try:
                    func_result = self._decompile_one(deci, func_name, lifted_addr, file_base)
                except Exception as e:
                    _l.debug("Failed to decompile %s: %s", func_name, e)
                    func_result = None

                if func_result is not None:
                    decompiled_functions[func_name] = func_result
                else:
                    failed_functions.append(func_name)

                _dump_progress()

        except Exception as e:
            _l.error("declib/%s failed on %s: %s", self.name, binary_path, e)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.name,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - start_time,
                    failed_functions=["all"],
                    extra={"error": str(e)},
                ),
            )
        finally:
            self._shutdown(deci)

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.name,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start_time,
                failed_functions=failed_functions,
                extra={"backend": self.force_decompiler, "via": "declib"},
            ),
            functions=decompiled_functions,
            output_dir=output_dir,
        )

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    def _make_deci(self, binary_path: Path, project_dir: Path | None) -> DecompilerInterface:
        """Create a headless declib interface for the binary."""
        from declib.api import DecompilerInterface

        kwargs: dict[str, Any] = {
            "force_decompiler": self.force_decompiler,
            "headless": True,
            "binary_path": str(binary_path),
        }
        if project_dir is not None:
            project_dir.mkdir(parents=True, exist_ok=True)
            kwargs["project_dir"] = str(project_dir)

        deci = DecompilerInterface.discover(**kwargs)
        if deci is None:
            raise RuntimeError(f"declib could not create a '{self.force_decompiler}' interface")
        return deci

    def _project_dir_for(self, binary_path: Path, output_dir: Path | None) -> Path | None:
        """Per-(binary, backend) cache dir; avoids project lock collisions."""
        if not self._uses_project_dir:
            return None
        # Ghidra forbids path elements starting with '.'.
        base = output_dir if output_dir is not None else binary_path.parent
        return base / f"declib_{self.name}_projects" / binary_path.stem

    def _file_space_base(
        self,
        deci: DecompilerInterface,
        binary_path: Path,
        header_base: int,
    ) -> int:
        """Return the file-space origin corresponding to declib's lifted zero."""
        info = binfmt.detect(binary_path)
        if info is None or info.fmt != "pe":
            return header_base
        try:
            backend_base = deci.binary_base_addr
        except Exception as e:
            raise RuntimeError(f"declib/{self.name} could not read the PE backend base: {e}") from e
        if isinstance(backend_base, bool) or not isinstance(backend_base, int) or backend_base < 0:
            raise RuntimeError(
                f"declib/{self.name} reported invalid PE backend base {backend_base!r}"
            )
        origins = _pe_file_space_origins(binary_path, header_base)
        if backend_base not in origins:
            allowed = ", ".join(f"{origin:#x}" for origin in sorted(origins))
            raise RuntimeError(
                f"declib/{self.name} reported non-canonical PE backend base "
                f"{backend_base:#x}; expected one of {allowed}"
            )
        return backend_base

    @staticmethod
    def _shutdown(deci: DecompilerInterface | None) -> None:
        if deci is None:
            return
        try:
            deci.shutdown()
        except Exception as e:
            _l.warning("declib shutdown failed: %s", e)

    def _enumerate_functions(
        self,
        deci: DecompilerInterface,
        binary_path: Path,
        elf_base: int,
        addr_targets: set[int] | None = None,
    ) -> list[tuple[str, int]]:
        """Enumerate (name, lifted_addr) for benchmarkable functions.

        Filters CRT/compiler helpers by name and anything outside file-backed
        executable ELF/PE sections, EXCEPT functions the driver explicitly
        asked for by address (:func:`raw_common.should_skip_function`).
        """
        code_ranges = raw_common.executable_code_ranges(binary_path)
        out: list[tuple[str, int]] = []
        for lifted_addr, light_func in deci.functions.items():
            name = light_func.name or ""
            file_addr = int(lifted_addr) + elf_base
            if raw_common.should_skip_function(name, file_addr, code_ranges, addr_targets):
                continue
            out.append((name, int(lifted_addr)))
        return sorted(out, key=lambda x: x[1])

    def _decompile_one(
        self,
        deci: DecompilerInterface,
        func_name: str,
        lifted_addr: int,
        elf_base: int,
    ) -> FunctionDecompilation | None:
        """Decompile a single function and collect text/lines/variables."""
        dec = deci.decompile(lifted_addr, map_lines=self.config.dump_line_mappings)
        if (dec is None or not dec.text) and self.config.dump_line_mappings:
            dec = deci.decompile(lifted_addr, map_lines=False)
        if dec is None or not dec.text:
            return None

        code = self._normalize_code(dec.text)

        function_size = self._function_size(deci, lifted_addr)
        line_mappings = self._extract_line_mappings(
            dec.line_map,
            code,
            lifted_addr,
            elf_base,
            function_size,
            address_offsets=self._line_map_address_offsets(deci),
        )
        variables = self._extract_variables(deci, lifted_addr)
        self._add_variable_evidence(variables, func_name, code, line_mappings)
        metadata = with_variable_occurrence_policy(
            self._extract_metrics(code), self._variable_occurrence_policy()
        )

        return FunctionDecompilation(
            name=func_name,
            address=lifted_addr + elf_base,
            decompiled_code=code,
            line_count=code.count("\n") + 1,
            line_mappings=line_mappings,
            variables=variables,
            metadata=metadata,
        )

    @staticmethod
    def _function_size(deci: DecompilerInterface, lifted_addr: int) -> int | None:
        try:
            value = deci.functions[lifted_addr].size
        except Exception as e:
            _l.debug("No function size at %#x: %s", lifted_addr, e)
            return None
        if isinstance(value, bool):
            return None
        try:
            size = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return size if size > 0 else None

    def _extract_line_mappings(
        self,
        raw_line_map: Any,
        code: str,
        lifted_addr: int,
        elf_base: int,
        function_size: int | None,
        *,
        address_offsets: tuple[int, ...] = (0,),
    ) -> list[LineMapping]:
        """Validate a backend's declib line contract and normalize it to 1-based rows."""
        if self._line_map_style not in {"one_based", "ida_zero_based"}:
            return []
        if not isinstance(raw_line_map, Mapping) or function_size is None:
            return []

        line_count = code.count("\n") + 1
        function_end = lifted_addr + function_size
        line_addresses: dict[int, set[int]] = defaultdict(set)
        ida_entry = False
        for raw_line, raw_addresses in raw_line_map.items():
            if isinstance(raw_line, bool) or not isinstance(raw_line, int):
                continue
            line_number = raw_line if self._line_map_style == "one_based" else raw_line + 1
            if not 1 <= line_number <= line_count:
                continue
            if isinstance(raw_addresses, (str, bytes, Mapping)):
                continue
            try:
                addresses = list(raw_addresses)
            except TypeError:
                continue
            for address in addresses:
                if isinstance(address, bool) or not isinstance(address, int):
                    continue
                candidates = {
                    address + offset
                    for offset in address_offsets
                    if lifted_addr <= address + offset < function_end
                }
                if len(candidates) != 1:
                    continue
                normalized_address = candidates.pop()
                if (
                    self._line_map_style == "ida_zero_based"
                    and raw_line == 1
                    and normalized_address == lifted_addr
                ):
                    ida_entry = True
                    continue
                line_addresses[line_number].add(normalized_address + elf_base)

        if ida_entry:
            line_addresses[1].add(lifted_addr + elf_base)
        return [
            LineMapping(line_number=line, addresses=sorted(addresses))
            for line, addresses in sorted(line_addresses.items())
            if addresses
        ]

    def _line_map_address_offsets(self, deci: DecompilerInterface) -> tuple[int, ...]:
        return (0,)

    def _variable_occurrence_policy(self) -> VariableOccurrencePolicy:
        return "exact" if self._line_map_style is not None else "unavailable"

    @staticmethod
    def _add_variable_evidence(
        variables: list[VariableInfo],
        function_name: str,
        code: str,
        line_mappings: list[LineMapping],
    ) -> None:
        if not variables or not line_mappings:
            return
        try:
            from decbench.metrics.variable_features import variable_occurrence_lines

            occurrence_lines = variable_occurrence_lines(
                code,
                function_name,
                (variable.name for variable in variables),
            )
        except Exception as e:
            _l.debug("Could not join declib variable occurrences in %s: %s", function_name, e)
            return

        line_addresses = {mapping.line_number: set(mapping.addresses) for mapping in line_mappings}
        for variable in variables:
            lines = list(occurrence_lines.get(variable.name, ()))
            if not lines:
                continue
            variable.line_numbers = lines
            variable.addresses = sorted(
                {address for line in lines for address in line_addresses.get(line, set())}
            )

    @staticmethod
    def _extract_variables(deci: DecompilerInterface, lifted_addr: int) -> list[VariableInfo]:
        """Pull stack variables and arguments from the full declib Function."""
        try:
            full_func = deci.functions[lifted_addr]
        except Exception as e:
            _l.debug("No full function at %#x: %s", lifted_addr, e)
            return []

        variables: list[VariableInfo] = []
        for offset, svar in (full_func.stack_vars or {}).items():
            variables.append(
                VariableInfo(
                    name=svar.name or "",
                    type=svar.type or "",
                    stack_offset=int(offset) if offset is not None else None,
                    size=svar.size,
                    kind="stack",
                )
            )

        header = full_func.header
        if header is not None and header.args:
            # Preserve ABI order so the type metric can match arguments positionally, even
            # when the decompiler invents names like a0/a1.
            for position, key in enumerate(sorted(header.args)):
                arg = header.args[key]
                variables.append(
                    VariableInfo(
                        name=arg.name or "",
                        type=arg.type or "",
                        stack_offset=None,
                        size=arg.size,
                        kind="arg",
                        arg_index=position,
                    )
                )

        return variables

    @staticmethod
    def _extract_metrics(code: str) -> dict[str, Any]:
        """Extract basic structure metrics from decompiled code."""
        return {
            "gotos": code.count("goto "),
            "bools": code.count(" && ") + code.count(" || "),
        }

    def _normalize_code(self, code: str) -> str:
        """Normalize decompiler-specific C dialect to standard C.

        Default is identity; backends override to strip non-standard syntax
        (so downstream metrics like byte_match can recompile the output).
        """
        return code


@register_decompiler("ida-declib")
class IDADeclibDecompiler(DeclibDecompiler):
    """IDA Pro (Hex-Rays) via declib + idalib (IDA 9+)."""

    name = "ida-declib"
    display_name = "IDA Pro (declib)"
    force_decompiler = "ida"
    _uses_project_dir = True
    _line_map_style = "ida_zero_based"

    _CODE_REPLACEMENTS = (
        ("unsigned __int64", "unsigned long long"),
        ("__int64", "long long"),
        ("__int32", "int"),
        ("__int16", "short"),
        ("__int8", "char"),
        ("_QWORD", "long long"),
        ("_DWORD", "int"),
        ("_WORD", "short"),
        ("_BYTE", "char"),
        ("_BOOL8", "long long"),
        ("_BOOL4", "int"),
        ("_BOOL", "_Bool"),
        ("__cdecl ", ""),
        ("__fastcall ", ""),
        ("__stdcall ", ""),
        ("__thiscall ", ""),
        ("__usercall ", ""),
        ("__golang ", ""),
        ("__noreturn ", ""),
    )

    def _normalize_code(self, code: str) -> str:
        """Normalize IDA-specific types and annotations to standard C."""
        for old, new in self._CODE_REPLACEMENTS:
            code = code.replace(old, new)
        return code

    def is_available(self) -> bool:
        try:
            import idapro  # noqa: F401

            return True
        except ImportError:
            try:
                import ida  # noqa: F401

                return True
            except ImportError:
                return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            import idaapi

            return str(idaapi.IDA_SDK_VERSION)
        except Exception:
            return "unknown"


@register_decompiler("ghidra-declib")
class GhidraDeclibDecompiler(DeclibDecompiler):
    """Ghidra via declib + pyghidra (requires GHIDRA_INSTALL_DIR)."""

    name = "ghidra-declib"
    display_name = "Ghidra (declib)"
    force_decompiler = "ghidra"
    _uses_project_dir = True
    _line_map_style = "one_based"

    def is_available(self) -> bool:
        if os.environ.get("GHIDRA_INSTALL_DIR") is None:
            return False
        try:
            import pyghidra  # noqa: F401

            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            ghidra_home = os.environ["GHIDRA_INSTALL_DIR"]
            version_file = Path(ghidra_home) / "Ghidra" / "application.properties"
            with open(version_file) as f:
                for line in f:
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
        except Exception:
            pass
        return "unknown"


@register_decompiler("binja-declib")
class BinjaDeclibDecompiler(DeclibDecompiler):
    """Binary Ninja via declib (requires a headless-capable license)."""

    name = "binja-declib"
    display_name = "Binary Ninja (declib)"
    force_decompiler = "binja"

    def is_available(self) -> bool:
        try:
            import binaryninja  # noqa: F401

            return True
        except Exception:
            return False

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            import binaryninja

            return str(binaryninja.core_version())
        except Exception:
            return "unknown"


@register_decompiler("angr-declib")
class AngrDeclibDecompiler(DeclibDecompiler):
    """angr's decompiler via declib (headless, no angr-management needed)."""

    name = "angr-declib"
    display_name = "angr (declib)"
    force_decompiler = "angr"
    _line_map_style = "one_based"

    def _line_map_address_offsets(self, deci: DecompilerInterface) -> tuple[int, ...]:
        try:
            binary_base = deci.binary_base_addr
        except Exception as e:
            _l.debug("Could not read angr's binary base for line mappings: %s", e)
            return (0,)
        if isinstance(binary_base, bool) or not isinstance(binary_base, int):
            return (0,)
        return tuple(sorted({0, binary_base}))

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
        except Exception:
            return "unknown"
