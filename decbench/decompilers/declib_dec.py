"""Decompiler plugins backed by the declib library.

All decompiler backends (IDA Pro, Ghidra, Binary Ninja, angr) are accessed
through declib's unified ``DecompilerInterface``, which handles headless
project management, decompilation, and artifact (variable/type) extraction.

Notes:
    - declib returns "lifted" addresses (rebased so the binary's first
      segment starts at 0). DecBench stores addresses in the ELF file's own
      address space (the same space DWARF uses), computed as
      ``lifted + min(PT_LOAD vaddr)``.
    - ``DecompilerConfig.function_timeout_seconds`` is advisory only:
      declib does not expose per-function decompilation timeouts.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)

if TYPE_CHECKING:
    from declib.api import DecompilerInterface

_l = logging.getLogger(__name__)

# CRT/compiler-generated functions that are not user code
_SKIP_NAMES = frozenset({
    "_start", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
    "_init", "_fini", "__do_global_dtors_aux", "register_tm_clones",
    "deregister_tm_clones", "frame_dummy", "__libc_start_call_main",
    "_dl_relocate_static_pie", "__gmon_start__", "__stack_chk_fail",
})

# Name prefixes for thunks/imports that should not be benchmarked
_SKIP_PREFIXES = ("thunk_", "j_", "__imp_", ".plt", "_dl_")


def _elf_min_vaddr(binary_path: Path) -> int:
    """Get the lowest PT_LOAD virtual address of an ELF file.

    Adding this to declib's lifted (0-based) addresses yields addresses in
    the ELF file's own address space, matching DWARF debug info regardless
    of where each decompiler chose to load the binary.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            vaddrs = [
                seg["p_vaddr"]
                for seg in elf.iter_segments()
                if seg["p_type"] == "PT_LOAD"
            ]
            return min(vaddrs) if vaddrs else 0
    except Exception as e:
        _l.debug("Failed to read ELF min vaddr for %s: %s", binary_path, e)
        return 0


def _elf_text_range(binary_path: Path) -> tuple[int, int] | None:
    """Get the [start, end) virtual address range of the .text section.

    Used to exclude PLT stubs and import thunks, which live in their own
    sections (.plt, .plt.sec) outside .text.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            if text is None:
                return None
            start = text["sh_addr"]
            return (start, start + text["sh_size"])
    except Exception as e:
        _l.debug("Failed to read .text range for %s: %s", binary_path, e)
        return None


class DeclibDecompiler(Decompiler):
    """Base class for decompilers driven through declib's DecompilerInterface."""

    name = "declib"
    display_name = "declib"
    # declib backend identifier passed to DecompilerInterface.discover()
    force_decompiler: str = ""
    # backends that benefit from a persistent project/cache directory
    _uses_project_dir: bool = False

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def get_version(self) -> str | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions using the declib backend."""
        if not self.is_available():
            return []

        elf_base = _elf_min_vaddr(binary_path)
        deci = None
        try:
            deci = self._make_deci(binary_path, None)
            return [
                (name, lifted_addr + elf_base)
                for name, lifted_addr in self._enumerate_functions(
                    deci, binary_path, elf_base
                )
            ]
        except Exception as e:
            _l.error("Failed to discover functions in %s: %s", binary_path, e)
            return []
        finally:
            self._shutdown(deci)

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary through declib."""
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        elf_base = _elf_min_vaddr(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        deci = None
        try:
            deci = self._make_deci(
                binary_path, self._project_dir_for(binary_path, output_dir)
            )

            if functions is not None:
                # Caller addresses are in ELF/DWARF space; declib wants lifted.
                target_funcs = [
                    (name, addr - elf_base) for name, addr in functions
                ]
            else:
                target_funcs = self._enumerate_functions(
                    deci, binary_path, elf_base
                )

            for func_name, lifted_addr in target_funcs:
                try:
                    func_result = self._decompile_one(
                        deci, func_name, lifted_addr, elf_base
                    )
                except Exception as e:
                    _l.debug("Failed to decompile %s: %s", func_name, e)
                    func_result = None

                if func_result is not None:
                    decompiled_functions[func_name] = func_result
                else:
                    failed_functions.append(func_name)

        except Exception as e:
            _l.error(
                "declib/%s failed on %s: %s", self.name, binary_path, e
            )
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

    def cleanup(self) -> None:
        """Per-binary interfaces are shut down inline; nothing persistent."""

    #
    # declib helpers
    #

    def _make_deci(
        self, binary_path: Path, project_dir: Path | None
    ) -> DecompilerInterface:
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
            raise RuntimeError(
                f"declib could not create a '{self.force_decompiler}' interface"
            )
        return deci

    def _project_dir_for(
        self, binary_path: Path, output_dir: Path | None
    ) -> Path | None:
        """Per-(binary, backend) cache dir; avoids project lock collisions."""
        if not self._uses_project_dir:
            return None
        # NOTE: Ghidra forbids path elements starting with '.'
        base = output_dir if output_dir is not None else binary_path.parent
        return base / f"declib_{self.name}_projects" / binary_path.stem

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
    ) -> list[tuple[str, int]]:
        """Enumerate (name, lifted_addr) for benchmarkable functions.

        Filters CRT/compiler helpers by name and anything outside the ELF
        .text section (PLT stubs, import thunks, simprocedures).
        """
        text_range = _elf_text_range(binary_path)
        out: list[tuple[str, int]] = []
        for lifted_addr, light_func in deci.functions.items():
            name = light_func.name or ""
            if not name or name in _SKIP_NAMES:
                continue
            if text_range is not None:
                # PLT stubs/import thunks live outside .text; inside .text we
                # trust the section filter and never drop by name prefix (a
                # user function may legitimately be called e.g. "j_compress").
                file_addr = int(lifted_addr) + elf_base
                if not (text_range[0] <= file_addr < text_range[1]):
                    continue
            elif name.startswith(_SKIP_PREFIXES):
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
        dec = deci.decompile(
            lifted_addr, map_lines=self.config.dump_line_mappings
        )
        if (dec is None or not dec.text) and self.config.dump_line_mappings:
            # Line mapping can fail independently of decompilation; retry
            # without it rather than losing the function entirely.
            dec = deci.decompile(lifted_addr, map_lines=False)
        if dec is None or not dec.text:
            return None

        code = self._normalize_code(dec.text)

        # declib line_map: {line_number: iterable[lifted_addr]} (set or list)
        line_mappings: list[LineMapping] = []
        if dec.line_map:
            for line_num, addrs in sorted(dec.line_map.items()):
                line_mappings.append(
                    LineMapping(
                        line_number=int(line_num),
                        addresses=sorted(int(a) + elf_base for a in addrs),
                    )
                )

        variables = self._extract_variables(deci, lifted_addr)
        metadata = self._extract_metrics(code)

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
    def _extract_variables(
        deci: DecompilerInterface, lifted_addr: int
    ) -> list[VariableInfo]:
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
            # declib keys args by positional index; preserve ABI order so the
            # type metric can match arguments positionally (works even when
            # the decompiler invents names like a0/a1).
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


@register_decompiler("ida")
class IDADeclibDecompiler(DeclibDecompiler):
    """IDA Pro (Hex-Rays) via declib + idalib (IDA 9+)."""

    name = "ida"
    display_name = "IDA Pro"
    force_decompiler = "ida"
    _uses_project_dir = True

    # IDA-specific C dialect -> standard C (order matters: __int64 first)
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
        # _Bool (not bool): compiles without <stdbool.h> when recompiled
        ("_BOOL", "_Bool"),
        # Calling-convention/attribute annotations gcc cannot parse
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


@register_decompiler("ghidra")
class GhidraDeclibDecompiler(DeclibDecompiler):
    """Ghidra via declib + pyghidra (requires GHIDRA_INSTALL_DIR)."""

    name = "ghidra"
    display_name = "Ghidra"
    force_decompiler = "ghidra"
    _uses_project_dir = True

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


@register_decompiler("binja")
class BinjaDeclibDecompiler(DeclibDecompiler):
    """Binary Ninja via declib (requires a headless-capable license)."""

    name = "binja"
    display_name = "Binary Ninja"
    force_decompiler = "binja"

    def is_available(self) -> bool:
        try:
            # License errors raise non-ImportError exceptions; treat any
            # failure as unavailable.
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


@register_decompiler("angr")
class AngrDeclibDecompiler(DeclibDecompiler):
    """angr's decompiler via declib (headless, no angr-management needed)."""

    name = "angr"
    display_name = "angr"
    force_decompiler = "angr"

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
