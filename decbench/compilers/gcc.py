"""GCC compiler implementation."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

from decbench.compilers.base import Compiler, CompileResult
from decbench.models.project import opt_gcc_flags
from decbench.utils.langs import PREPROC_EXTS, SOURCE_EXTS, preprocessed_ext

# Build by-products that are never a linked binary, so they are skipped before
# the (more expensive) ELF/PE sniff.
_NON_BINARY_EXTS = (".o", ".a", ".s", ".h", ".hh", ".hpp", *PREPROC_EXTS, *SOURCE_EXTS)


def find_preprocessed(base_path: Path) -> Path | None:
    """First existing ``base_path`` re-suffixed with a preprocessed extension."""
    for ext in PREPROC_EXTS:
        candidate = base_path.with_suffix(ext)
        if candidate.exists():
            return candidate
    return None


class GCCCompiler(Compiler):
    """GCC-based compiler."""

    name = "gcc"

    def __init__(
        self,
        gcc_path: str | None = None,
        base_flags: list[str] | None = None,
        target_arch: str | None = None,
    ):
        """Initialize GCC compiler.

        Args:
            gcc_path: Path to gcc binary, or None to use PATH
            base_flags: Base compiler flags always applied
            target_arch: If set (e.g. 'arm'), only collect ELF binaries of this
                machine architecture from make-based builds (drops incidental
                host tools from cross-compiled projects).
        """
        self.gcc_path = gcc_path or self._find_gcc()
        self.target_arch = target_arch

        # Inlining is governed by the optimization level (O2-noinline), not by these
        # base flags, so plain O2 stays a genuine O2.
        self.base_flags = base_flags or [
            "-g",
            "-fno-builtin",
        ]

    def _find_gcc(self) -> str | None:
        """Find GCC in PATH."""
        for version in ["13", "12", "11", "10", "9", ""]:
            name = f"gcc-{version}" if version else "gcc"
            path = shutil.which(name)
            if path:
                return path

        return "gcc"

    def is_available(self) -> bool:
        """Check if GCC is available."""
        try:
            result = subprocess.run(
                [self.gcc_path, "--version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> str | None:
        """Get GCC version."""
        try:
            result = subprocess.run(
                [self.gcc_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.split("\n")[0]
        except Exception:
            pass
        return None

    def compile(
        self,
        source_path: Path,
        output_dir: Path,
        optimization: str = "O2",
        extra_flags: list[str] | None = None,
        emit_preprocessed: bool = True,
    ) -> CompileResult:
        """Compile a single source file."""
        source_path = Path(source_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        stem = source_path.stem
        object_path = output_dir / f"{stem}.o"
        pp_ext = preprocessed_ext(source_path)
        preprocessed_path = output_dir / f"{stem}{pp_ext}" if emit_preprocessed else None

        flags = list(self.base_flags)
        flags.extend(opt_gcc_flags(optimization))

        if emit_preprocessed:
            flags.append("-save-temps=obj")

        if extra_flags:
            flags.extend(extra_flags)

        cmd = [
            self.gcc_path,
            *flags,
            "-c",
            "-o", str(object_path),
            str(source_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=output_dir,
            )

            if result.returncode != 0:
                return CompileResult(
                    source_path=source_path,
                    success=False,
                    error_message=result.stderr,
                )

            if emit_preprocessed and not preprocessed_path.exists():
                alt_path = source_path.with_suffix(pp_ext)
                if alt_path.exists():
                    shutil.move(str(alt_path), str(preprocessed_path))

            return CompileResult(
                source_path=source_path,
                object_path=object_path if object_path.exists() else None,
                preprocessed_path=(
                    preprocessed_path
                    if preprocessed_path and preprocessed_path.exists()
                    else None
                ),
                success=object_path.exists(),
            )

        except subprocess.TimeoutExpired:
            return CompileResult(
                source_path=source_path,
                success=False,
                error_message="Compilation timed out",
            )
        except Exception as e:
            return CompileResult(
                source_path=source_path,
                success=False,
                error_message=str(e),
            )

    @staticmethod
    def _is_elf_executable(path: Path) -> bool:
        """Check if a file is a linked ELF binary (executable or shared object)."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return False
                f.seek(16)
                e_type = struct.unpack("<H", f.read(2))[0]
                return e_type in (2, 3)
        except (OSError, struct.error):
            return False

    _ELF_MACHINES = {
        0x28: "arm", 0xB7: "aarch64", 0x3E: "x86-64", 0x03: "x86",
        0xF3: "riscv", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64",
    }

    @classmethod
    def _elf_machine(cls, path: Path) -> str | None:
        """Return the short architecture name of an ELF (e_machine), or None."""
        try:
            with open(path, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    return None
                f.seek(18)
                return cls._ELF_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
        except (OSError, struct.error):
            return None

    _PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "aarch64", 0x1C0: "arm"}

    @staticmethod
    def _is_pe_executable(path: Path) -> bool:
        """Check if a file is a PE (Windows) executable/DLL (MinGW output)."""
        try:
            with open(path, "rb") as f:
                if f.read(2) != b"MZ":
                    return False
                f.seek(0x3C)
                pe_off = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_off)
                return f.read(4) == b"PE\x00\x00"
        except (OSError, struct.error):
            return False

    @classmethod
    def _is_linked_binary(cls, path: Path) -> bool:
        """A linked executable the decompilers can load: ELF (exec/dyn) or PE.

        PE support lets the malware targets (Windows C cross-compiled with MinGW)
        be collected alongside the ELF targets.
        """
        return cls._is_elf_executable(path) or cls._is_pe_executable(path)

    @classmethod
    def _binary_machine(cls, path: Path) -> str | None:
        """Short arch name for an ELF or PE binary (for the target_arch filter)."""
        m = cls._elf_machine(path)
        if m is not None:
            return m
        try:
            with open(path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
                f.seek(0x3C)
                pe_off = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_off)
                if f.read(4) != b"PE\x00\x00":
                    return None
                return cls._PE_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
        except (OSError, struct.error):
            return None

    def compile_project(
        self,
        project_dir: Path,
        output_dir: Path,
        optimization: str = "O2",
        source_pattern: str = "**/*.c",
        pre_commands: list[str] | None = None,
        make_command: str | None = None,
        extra_flags: list[str] | None = None,
        project_root: Path | None = None,
    ) -> list[CompileResult]:
        """Compile an entire project."""
        project_dir = Path(project_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if project_root is None:
            project_root = project_dir
        else:
            project_root = Path(project_root)

        results = []

        env = os.environ.copy()
        cflags = " ".join(self.base_flags + opt_gcc_flags(optimization))
        if extra_flags:
            cflags += " " + " ".join(extra_flags)

        env["CFLAGS"] = cflags
        env["CC"] = self.gcc_path

        if pre_commands:
            for cmd in pre_commands:
                try:
                    subprocess.run(
                        cmd,
                        shell=True,
                        cwd=project_root,
                        env=env,
                        timeout=600,
                        check=True,
                    )
                except subprocess.CalledProcessError as e:
                    pass

        if make_command:
            try:
                subprocess.run(
                    make_command,
                    shell=True,
                    cwd=project_root,
                    env=env,
                    timeout=3600,
                    check=True,
                )

                for entry in project_dir.rglob("*"):
                    if not entry.is_file():
                        continue
                    if entry.is_symlink():
                        continue
                    if entry.suffix in _NON_BINARY_EXTS:
                        continue
                    if not self._is_linked_binary(entry):
                        continue
                    if self.target_arch and self._binary_machine(entry) != self.target_arch:
                        continue

                    dest_bin = output_dir / entry.name
                    shutil.copy2(entry, dest_bin)

                    obj_file = entry.with_suffix(".o")
                    c_file = entry.with_suffix(".c")
                    i_file = find_preprocessed(entry)
                    dest_i = None
                    if i_file is not None:
                        dest_i = output_dir / i_file.name
                        shutil.copy2(i_file, dest_i)
                    elif obj_file.exists():
                        alt_i = find_preprocessed(obj_file)
                        if alt_i is not None:
                            dest_i = output_dir / alt_i.name
                            shutil.copy2(alt_i, dest_i)

                    results.append(CompileResult(
                        source_path=c_file if c_file.exists() else entry,
                        object_path=dest_bin,
                        preprocessed_path=dest_i,
                        success=True,
                    ))

                for obj_file in project_dir.rglob("*.o"):
                    i_file = find_preprocessed(obj_file)
                    if i_file is not None:
                        dest_i = output_dir / i_file.name
                        if not dest_i.exists():
                            shutil.copy2(i_file, dest_i)

            except subprocess.CalledProcessError as e:
                results.append(CompileResult(
                    source_path=project_dir,
                    success=False,
                    error_message=f"Make failed: {e}",
                ))

        else:
            source_files = list(project_dir.glob(source_pattern))

            for source_file in source_files:
                result = self.compile(
                    source_file,
                    output_dir,
                    optimization=optimization,
                    extra_flags=extra_flags,
                    emit_preprocessed=True,
                )
                results.append(result)

        return results
