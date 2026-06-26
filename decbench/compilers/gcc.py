"""GCC compiler implementation."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

from decbench.compilers.base import Compiler, CompileResult
from decbench.models.project import opt_gcc_flags


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

        # Default base flags for reproducible decompilation benchmarking.
        # Inlining is governed by the optimization level (O2-noinline), not
        # base flags, so plain O2 stays a genuine O2.
        self.base_flags = base_flags or [
            "-g",  # Debug symbols
            "-fno-builtin",  # Don't use builtin optimizations
        ]

    def _find_gcc(self) -> str | None:
        """Find GCC in PATH."""
        # Try versioned GCC first
        for version in ["13", "12", "11", "10", "9", ""]:
            name = f"gcc-{version}" if version else "gcc"
            path = shutil.which(name)
            if path:
                return path

        return "gcc"  # Default, may fail if not found

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
                # First line contains version
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

        # Output paths
        stem = source_path.stem
        object_path = output_dir / f"{stem}.o"
        preprocessed_path = output_dir / f"{stem}.i" if emit_preprocessed else None

        # Build command
        flags = list(self.base_flags)
        flags.extend(opt_gcc_flags(optimization))

        if emit_preprocessed:
            flags.append("-save-temps=obj")

        if extra_flags:
            flags.extend(extra_flags)

        cmd = [
            self.gcc_path,
            *flags,
            "-c",  # Compile only, no linking
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

            # Find preprocessed file (may be in different location)
            if emit_preprocessed and not preprocessed_path.exists():
                # Check if it was created next to source
                alt_path = source_path.with_suffix(".i")
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
                # e_type is at offset 16, 2 bytes little-endian
                f.seek(16)
                e_type = struct.unpack("<H", f.read(2))[0]
                # ET_EXEC = 2 (executable), ET_DYN = 3 (shared/PIE)
                return e_type in (2, 3)
        except (OSError, struct.error):
            return False

    # ELF e_machine -> short arch name (the ones we cross-compile for / against).
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
                f.seek(18)  # e_machine
                return cls._ELF_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
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

        # project_root is where configure/make run from (the repo root).
        # project_dir is where source files live (may be a subdirectory).
        if project_root is None:
            project_root = project_dir
        else:
            project_root = Path(project_root)

        results = []

        # Set up environment with our compiler flags
        env = os.environ.copy()
        cflags = " ".join(self.base_flags + opt_gcc_flags(optimization))
        if extra_flags:
            cflags += " " + " ".join(extra_flags)

        env["CFLAGS"] = cflags
        env["CC"] = self.gcc_path

        # Run pre-commands (e.g., ./configure) from the project root
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
                    # Pre-command failed, but continue
                    pass

        # Use make if specified
        if make_command:
            try:
                subprocess.run(
                    make_command,
                    shell=True,
                    cwd=project_root,
                    env=env,
                    timeout=3600,  # 1h timeout for large serial builds (e.g. gnutls)
                    check=True,
                )

                # Find linked ELF executables for decompilation.
                # Decompilers need linked binaries (ET_EXEC/ET_DYN),
                # not relocatable .o files (ET_REL).
                for entry in project_dir.rglob("*"):
                    if not entry.is_file():
                        continue
                    if entry.is_symlink():
                        # Library builds symlink lib.so -> lib.so.X -> lib.so.X.Y.Z;
                        # only collect the real file once.
                        continue
                    if entry.suffix in (".o", ".a", ".i", ".s", ".c", ".h"):
                        continue
                    if not self._is_elf_executable(entry):
                        continue
                    # For cross-compiled projects, skip incidental host tools
                    # (e.g. x86 mkimage) and keep only the target-arch binaries.
                    if self.target_arch and self._elf_machine(entry) != self.target_arch:
                        continue

                    dest_bin = output_dir / entry.name
                    shutil.copy2(entry, dest_bin)

                    # Find matching .c and .i files via the .o file
                    obj_file = entry.with_suffix(".o")
                    c_file = entry.with_suffix(".c")
                    i_file = entry.with_suffix(".i")
                    dest_i = None
                    if i_file.exists():
                        dest_i = output_dir / i_file.name
                        shutil.copy2(i_file, dest_i)
                    elif obj_file.exists():
                        # .i file may be named after the .o file
                        alt_i = obj_file.with_suffix(".i")
                        if alt_i.exists() and alt_i != i_file:
                            dest_i = output_dir / alt_i.name
                            shutil.copy2(alt_i, dest_i)

                    results.append(CompileResult(
                        source_path=c_file if c_file.exists() else entry,
                        object_path=dest_bin,
                        preprocessed_path=dest_i,
                        success=True,
                    ))

                # Also copy .i and .o files for source CFG extraction
                for obj_file in project_dir.rglob("*.o"):
                    i_file = obj_file.with_suffix(".i")
                    if i_file.exists():
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
            # Compile individual files
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
