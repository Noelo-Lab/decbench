"""Raw dewolf decompiler backend (github.com/fkie-cad/dewolf).

dewolf is a Binary-Ninja-based research decompiler pinned to ``z3-solver==4.8.10``
and Python 3.10, so it cannot share decbench's (3.14) interpreter. This backend
runs the decompilation OUT OF PROCESS, in the dewolf virtualenv, via
:mod:`decbench.decompilers.raw.dewolf_driver`: that driver does the Binary Ninja
analysis once per binary and streams one JSON object per function back on stdout,
which this backend turns into :class:`FunctionDecompilation` objects with
ELF-file-space addresses (so they line up with DWARF for scoring).

Configuration (``~/.config/decbench/decompilers.toml`` ``[dewolf.versions."X"]``
or the environment):

* ``python`` / ``DECBENCH_DEWOLF_PYTHON`` — the dewolf venv's interpreter.
* ``repo`` / ``DECBENCH_DEWOLF_REPO`` — the dewolf checkout (added to
  ``PYTHONPATH`` so ``import decompile`` resolves).
* ``astyle_path`` / ``DECBENCH_DEWOLF_ASTYLE`` — optional dir prepended to
  ``PATH`` so dewolf finds ``astyle`` for output indentation.

Like the other raw backends it drives a fully-stripped binary and filters to the
project's source functions BY ADDRESS (``function_names`` is a set of ints), with
per-function partial-progress checkpointing so a timeout still yields the
functions completed so far.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

_l = logging.getLogger(__name__)

_DRIVER = Path(__file__).with_name("dewolf_driver.py")


@register_decompiler("dewolf")
class RawDewolfDecompiler(Decompiler):
    """dewolf driven out-of-process in its own venv (Binary Ninja frontend)."""

    name = "dewolf"
    display_name = "dewolf"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    #
    # Config resolution
    #

    def _settings(self) -> dict:
        """Per-version settings, falling back to the ``default`` entry.

        The bare ``dewolf`` spec has no requested version, so read the
        ``[dewolf.versions.default]`` table for it; an explicit ``dewolf@X`` reads
        its own table.
        """
        from decbench.decompilers.spec import version_settings

        settings = version_settings("dewolf", self.requested_version)
        if not settings and self.requested_version is None:
            settings = version_settings("dewolf", "default")
        return settings

    def _python(self) -> str | None:
        """The dewolf venv interpreter (config > env)."""
        return self._settings().get("python") or os.environ.get("DECBENCH_DEWOLF_PYTHON")

    def _repo(self) -> str | None:
        """The dewolf checkout added to PYTHONPATH (config > env)."""
        return self._settings().get("repo") or os.environ.get("DECBENCH_DEWOLF_REPO")

    def _astyle_dir(self) -> str | None:
        return self._settings().get("astyle_path") or os.environ.get("DECBENCH_DEWOLF_ASTYLE")

    def _child_env(self) -> dict[str, str]:
        env = dict(os.environ)
        repo = self._repo()
        if repo:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = repo + (os.pathsep + existing if existing else "")
        astyle = self._astyle_dir()
        if astyle:
            env["PATH"] = astyle + os.pathsep + env.get("PATH", "")
        return env

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        python = self._python()
        if not python or not Path(python).exists():
            return False
        return _DRIVER.exists()

    def get_version(self) -> str | None:
        repo = self._repo()
        if not repo:
            return None
        try:
            out = subprocess.run(
                ["git", "-C", repo, "describe", "--tags", "--always"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:  # noqa: BLE001
            pass
        return "unknown"

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile ``binary_path`` via the out-of-process dewolf driver."""
        if not self.is_available():
            raise RuntimeError(f"Decompiler '{self.name}' is not available")

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        failed_functions: list[str] = []

        # The driver filters by address itself; pass the int targets through.
        target_addrs = {a for a in (function_names or set()) if isinstance(a, int)} or None
        addrs_arg = json.dumps(sorted(target_addrs)) if target_addrs else "NONE"

        def _meta(partial: bool, error: str | None = None) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "dewolf", "via": "raw"}
            if partial:
                extra["partial"] = True
            if error:
                extra["error"] = error
                extra["failure"] = error
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start_time,
                failed_functions=list(failed_functions),
                extra=extra,
            )

        def _dump() -> None:
            if progress_path is None:
                return
            partial = DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=_meta(partial=True),
                functions=dict(decompiled_functions),
                output_dir=output_dir,
            )
            common.dump_progress(progress_path, partial)

        cmd = [str(self._python()), str(_DRIVER), str(binary_path), str(elf_base), addrs_arg]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._child_env(),
                text=True,
                bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            _l.error("dewolf-raw failed to launch on %s: %s", binary_path, exc)
            return self._error_result(binary_path, start_time, str(exc))

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = obj.get("type")
                if kind == "func":
                    name = str(obj.get("name") or "")
                    code = obj.get("code") or ""
                    if not name or not code:
                        continue
                    decompiled_functions[name] = FunctionDecompilation(
                        name=name,
                        address=int(obj.get("addr", 0)),
                        decompiled_code=code,
                        line_count=code.count("\n") + 1,
                        line_mappings=[],
                        variables=[],
                        metadata=common.extract_metrics(code),
                    )
                    _dump()
                elif kind == "fail":
                    failed_functions.append(str(obj.get("name") or obj.get("addr")))
        finally:
            proc.wait()

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=_meta(partial=False),
            functions=decompiled_functions,
            output_dir=output_dir,
        )

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    def _error_result(
        self, binary_path: Path, start_time: float, error: str
    ) -> DecompilationResult:
        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start_time,
                failed_functions=["all"],
                extra={"error": error, "backend": "dewolf", "via": "raw"},
            ),
        )
