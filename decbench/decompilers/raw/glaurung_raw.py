"""Raw Glaurung decompiler backend (native, via the glaurung CLI).

Glaurung (https://github.com/…/glaurung) is an AI-native reverse-engineering
framework whose decompiler is a pure-Rust LLIR pipeline (CFG discovery → lift →
SSA → control-flow structuring → AST lowering → expression reconstruction → DCE
→ name/arg/type recovery). Like ``kuna``, it ships as a standalone CLI, so this
backend *shells out* to it and parses JSON rather than importing a native Python
module.

It drives Glaurung's ``decompile`` command in its parseable-C mode
(``--style decbench``), which emits a valid C translation-unit fragment per
function — a real ``long name(long arg0, …)`` signature with declared locals —
so DecBench's Joern-based GED and the C-signature type_match parser can consume
it. Two invocation shapes, both load-once/decompile-many in a single process:

* target-scoped (the benchmark case) — decompile exactly the DWARF target VAs::

      glaurung decompile <binary> --vas <va,va,…> --style decbench --format json

* whole-binary fallback (bare ``decbench run`` with no target set)::

      glaurung decompile <binary> --all --limit <N> --style decbench --format json

Both emit ``[{"name": …, "entry_va": <int>, "pseudocode": "<C>"}, …]``.

Glaurung reports entry VAs in the ELF's own link/file space (same as
ida/binja/kuna on non-PIE ELFs), so ``entry_va`` is used as the DecBench
``address`` directly — **no ``elf_min_vaddr`` rebasing**. The benchmarkable-set
filtering (CRT/PLT exclusion, DWARF source-address narrowing) is applied here
with the shared ``common`` helpers, exactly like the other raw backends.

Architecture support: x86-64, AArch64, and **ARM32/Thumb-2** (the DecBench CPS
firmware is Cortex-M Thumb, so this covers the ARM slice). A32-only binaries are
a documented follow-up; Glaurung decodes ARM as Thumb by default. Structured
``VariableInfo`` is not emitted yet; type_match uses its C-signature text-parsing
path over the emitted ``long name(long arg0, …)`` prototype.

Locate the CLI via ``$GLAURUNG_BIN`` (an explicit path) or ``glaurung`` on
``$PATH``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
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

# Above this many targets we skip the (command-line-length-bounded) --vas form
# and decompile the whole binary, then narrow. The sample-set takes at most one
# function per binary, so --vas is the normal path; this is just a safety valve.
_MAX_VAS_INLINE = 400


@register_decompiler("glaurung")
class RawGlaurungDecompiler(Decompiler):
    """Glaurung (native Rust LLIR decompiler) driven via its CLI."""

    name = "glaurung"
    display_name = "Glaurung"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._payload_cache: dict[str, Any] = {}

    #
    # Locating the binary (mirrors kuna_raw's $KUNA_BIN / which)
    #

    @staticmethod
    def _glaurung_bin() -> str | None:
        env = os.environ.get("GLAURUNG_BIN")
        if env and Path(env).is_file():
            return env
        return shutil.which("glaurung")

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        return self._glaurung_bin() is not None

    def get_version(self) -> str | None:
        exe = self._glaurung_bin()
        if not exe:
            return None
        try:
            p = subprocess.run(
                [exe, "--version"], capture_output=True, text=True, timeout=30
            )
            out = (p.stdout or p.stderr or "").strip()
            m = re.search(r"(\d+\.\d+\.\d+\S*)", out)
            if m:
                return m.group(1)
            return out.splitlines()[0] if out else "unknown"
        except Exception:  # noqa: BLE001
            return "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-file-space addr) for the benchmarkable functions."""
        if not self.is_available():
            return []
        try:
            records = self._run_decompile(binary_path, function_names=None)
        except Exception as e:  # noqa: BLE001
            _l.error("glaurung-raw: discover failed on %s: %s", binary_path, e)
            return []
        text_range = common.elf_text_range(binary_path)
        out = [
            (str(r.get("name") or ""), int(r.get("entry_va") or 0)) for r in records
        ]
        out = [
            (n, a) for (n, a) in out if not common.should_skip_function(n, a, text_range)
        ]
        return sorted(out, key=lambda x: x[1])

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a whole binary (one CLI invocation, load-once)."""
        if not self.is_available():
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available "
                f"(glaurung CLI not found; set $GLAURUNG_BIN or add it to PATH)"
            )

        start = time.time()
        text_range = common.elf_text_range(binary_path)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        timed_out = False

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "glaurung", "via": "raw"}
            if partial:
                extra["partial"] = True
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                timeout_occurred=timed_out,
                failed_functions=list(failed),
                extra=extra,
            )

        def _dump() -> None:
            if progress_path is None:
                return
            common.dump_progress(
                progress_path,
                DecompilationResult(
                    binary_path=binary_path,
                    binary_name=binary_path.stem,
                    decompiler=_meta(partial=True),
                    functions=dict(decompiled),
                    output_dir=output_dir,
                ),
            )

        # 1. One CLI invocation for the requested target set (load once).
        try:
            records = self._run_decompile(binary_path, function_names=function_names)
        except subprocess.TimeoutExpired as e:
            timed_out = True
            _l.warning("glaurung-raw timed out on %s: %s", binary_path, e)
            return self._error_result(binary_path, start, "timeout", timed_out=True)
        except Exception as e:  # noqa: BLE001
            _l.error("glaurung-raw failed on %s: %s", binary_path, e)
            return self._error_result(binary_path, start, str(e))

        # 2. Index by name, filter to the benchmarkable + source-narrowed set.
        by_name = {str(r.get("name") or ""): r for r in records}
        enumerated = sorted(
            (
                (n, int(r.get("entry_va") or 0))
                for n, r in by_name.items()
                if not common.should_skip_function(
                    n, int(r.get("entry_va") or 0), text_range
                )
            ),
            key=lambda x: x[1],
        )
        if functions is not None:
            requested = {n for (n, _a) in functions}
            enumerated = [(n, a) for (n, a) in enumerated if n in requested]
        enumerated = common.narrow_to_source(
            enumerated, function_names, backend="glaurung", binary_name=binary_path.name
        )

        for func_name, file_addr in enumerated:
            fd = None
            try:
                fd = self._build_function(by_name[func_name], func_name, file_addr)
            except Exception as e:  # noqa: BLE001
                _l.debug("glaurung-raw: assembling %s failed: %s", func_name, e)
            if fd is not None:
                decompiled[func_name] = fd
            else:
                failed.append(func_name)
            _dump()

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=_meta(partial=False),
            functions=decompiled,
            output_dir=output_dir,
        )
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")
        return result

    #
    # glaurung CLI plumbing
    #

    def _build_command(
        self, binary_path: Path, function_names: set[int] | None
    ) -> list[str]:
        exe = self._glaurung_bin()
        assert exe is not None
        cmd = [exe, "decompile", str(binary_path), "--style", "decbench", "--format", "json"]
        # Target-scoped when we know the DWARF target set and it is small enough
        # for the command line; otherwise decompile the whole binary and narrow.
        if function_names and len(function_names) <= _MAX_VAS_INLINE:
            cmd += ["--vas", ",".join(hex(int(a)) for a in sorted(function_names))]
        else:
            limit = os.environ.get("DECBENCH_GLAURUNG_LIMIT", "30000")
            cmd += ["--all", "--limit", str(int(limit))]
        # Optional per-function analysis budget (ms). Glaurung bounds each
        # function's lift/structure work; this caps a pathological single
        # function without failing the batch.
        fn_ms = os.environ.get("DECBENCH_GLAURUNG_TIMEOUT_MS")
        if fn_ms:
            cmd += ["--timeout-ms", str(int(fn_ms))]
        return cmd

    @staticmethod
    def _kill_group(p: subprocess.Popen) -> None:
        """SIGKILL glaurung's whole process group (pgid == pid via start_new_session)."""
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                pass
        try:
            p.wait(timeout=15)
        except Exception:  # noqa: BLE001
            pass

    def _timeout_seconds(self) -> float | None:
        env = os.environ.get("DECBENCH_GLAURUNG_TIMEOUT")
        if env:
            try:
                return int(env)
            except ValueError:
                _l.warning("ignoring non-integer DECBENCH_GLAURUNG_TIMEOUT=%r", env)
        return self.config.binary_timeout_seconds

    def _run_decompile(
        self, binary_path: Path, function_names: set[int] | None
    ) -> list[dict[str, Any]]:
        """Run ``glaurung decompile … --format json`` and parse the JSON list.

        Cached per (resolved path, target-set) so ``discover_functions`` +
        ``decompile_binary`` don't pay for two loads.
        """
        key = (str(binary_path), None if function_names is None else frozenset(function_names))
        if key in self._payload_cache:
            return self._payload_cache[key]
        cmd = self._build_command(binary_path, function_names)
        _l.debug("glaurung run: %s", " ".join(cmd))
        # start_new_session=True so a timeout can SIGKILL the WHOLE tree; this
        # backend then owns the kill on every exit path.
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = p.communicate(timeout=self._timeout_seconds())
        finally:
            if p.poll() is None:
                self._kill_group(p)
        if p.returncode != 0 and not (stdout or "").strip():
            tail = (stderr or "")[-500:]
            raise RuntimeError(f"glaurung exited {p.returncode}: {tail}")
        records = self._parse_records(stdout)
        self._payload_cache[key] = records
        return records

    @staticmethod
    def _parse_records(stdout: str) -> list[dict[str, Any]]:
        """Parse the CLI's JSON, tolerating a single-object (single-function) form."""
        text = (stdout or "").strip()
        if not text:
            return []
        payload = json.loads(text)
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        if isinstance(payload, dict):
            return [payload]
        return []

    def _build_function(
        self, rec: dict[str, Any], name: str, file_addr: int
    ) -> FunctionDecompilation | None:
        code = rec.get("pseudocode")
        if not code or not str(code).strip():
            return None
        code = str(code)
        return FunctionDecompilation(
            name=name,
            address=file_addr,
            decompiled_code=code,
            line_count=code.count("\n") + 1,
            line_mappings=[],  # not emitted; GED parses the C directly
            variables=[],  # v1: type_match uses the C-signature text path
            metadata=common.extract_metrics(code),
        )

    def _error_result(
        self, binary_path: Path, start: float, err: str, timed_out: bool = False
    ) -> DecompilationResult:
        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                timeout_occurred=timed_out,
                failed_functions=["all"],
                extra={"error": err, "backend": "glaurung", "via": "raw"},
            ),
        )
