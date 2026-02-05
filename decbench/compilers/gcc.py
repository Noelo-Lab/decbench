"""GCC compiler implementation."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from decbench.compilers.base import Compiler, CompileResult


class GCCCompiler(Compiler):
    """GCC-based compiler."""

    name = "gcc"

    def __init__(
        self,
        gcc_path: str | None = None,
        base_flags: list[str] | None = None,
    ):
        """Initialize GCC compiler.

        Args:
            gcc_path: Path to gcc binary, or None to use PATH
            base_flags: Base compiler flags always applied
        """
        self.gcc_path = gcc_path or self._find_gcc()

        # Default base flags for reproducible decompilation benchmarking
        self.base_flags = base_flags or [
            "-g",  # Debug symbols
            "-fno-inline",  # Don't inline functions
            "-fno-builtin",  # Don't use builtin optimizations
        ]

    def _find_gcc(self) -> str:
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
        flags.append(f"-{optimization}")

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
                preprocessed_path=preprocessed_path if preprocessed_path and preprocessed_path.exists() else None,
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

    def compile_project(
        self,
        project_dir: Path,
        output_dir: Path,
        optimization: str = "O2",
        source_pattern: str = "**/*.c",
        pre_commands: list[str] | None = None,
        make_command: str | None = None,
        extra_flags: list[str] | None = None,
    ) -> list[CompileResult]:
        """Compile an entire project."""
        project_dir = Path(project_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        results = []

        # Set up environment with our compiler flags
        env = os.environ.copy()
        cflags = " ".join(self.base_flags + [f"-{optimization}"])
        if extra_flags:
            cflags += " " + " ".join(extra_flags)

        env["CFLAGS"] = cflags
        env["CC"] = self.gcc_path

        # Run pre-commands (e.g., ./configure)
        if pre_commands:
            for cmd in pre_commands:
                try:
                    subprocess.run(
                        cmd,
                        shell=True,
                        cwd=project_dir,
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
                    cwd=project_dir,
                    env=env,
                    timeout=1800,  # 30 min timeout for large projects
                    check=True,
                )

                # Find generated .o files
                for obj_file in project_dir.rglob("*.o"):
                    # Try to find matching .c file
                    c_file = obj_file.with_suffix(".c")
                    if not c_file.exists():
                        c_file = None

                    # Copy to output
                    dest_obj = output_dir / obj_file.name
                    shutil.copy2(obj_file, dest_obj)

                    # Look for .i file
                    i_file = obj_file.with_suffix(".i")
                    dest_i = None
                    if i_file.exists():
                        dest_i = output_dir / i_file.name
                        shutil.copy2(i_file, dest_i)

                    results.append(CompileResult(
                        source_path=c_file or obj_file.with_suffix(".c"),
                        object_path=dest_obj,
                        preprocessed_path=dest_i,
                        success=True,
                    ))

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
