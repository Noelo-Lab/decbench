"""Raw kuna decompiler backend (no declib), via the kuna CLI.

Unlike the angr/ghidra/ida/binja raw backends — which import a native Python
module (angr, pyghidra, idalib, binaryninja) and decompile in-process — kuna
ships as a standalone Rust CLI (a line-faithful port of Ghidra's decompiler).
So this backend *shells out* to it and parses JSON, the way the dockerized
backends shell out to a container.

It drives kuna's **whole-binary** entrypoint, which loads + analyzes the binary
once and decompiles every function from that single load (the load-once contract
decbench's ghidra/angr backends satisfy by reusing one program/JVM/process):

    kuna decompile-all <binary> --json

emitting ::

    {"binary": "...", "count": N, "functions": [
        {"name": "main", "address": <elf-file-space int>, "address_hex": "0x..",
         "size": <int>, "code": "<C>" | null, "error": null | "<msg>",
         "variables": [
            {"name": "..", "type": "..", "kind": "arg" | "stack",
             "arg_index": <int> | null, "stack_offset": <int> | null,
             "size": <int>}]},
        ...]}

kuna is a Ghidra-decompiler port, so its addresses are already in the ELF's
link/file space (same as ida/binja on non-PIE ELFs) — no rebasing needed. The
benchmarkable-set filtering (CRT/PLT/thunk exclusion, source-name narrowing) is
applied here with the shared ``common`` helpers, exactly like the other raw
backends, so kuna's enumerated set matches theirs.

Locate the CLI via ``$KUNA_BIN`` (an explicit path) or ``kuna`` on ``$PATH``.
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
    VariableInfo,
)

_l = logging.getLogger(__name__)


@register_decompiler("kuna")
class RawKunaDecompiler(Decompiler):
    """kuna (Rust Ghidra-decompiler port) driven via its CLI, without declib."""

    name = "kuna"
    display_name = "kuna"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._payload_cache: dict[str, Any] = {}

    #
    # Locating the binary (mirrors ghidra_raw's GHIDRA_INSTALL_DIR / docker's which)
    #

    @staticmethod
    def _kuna_bin() -> str | None:
        env = os.environ.get("KUNA_BIN")
        if env and Path(env).is_file():
            return env
        return shutil.which("kuna")

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        return self._kuna_bin() is not None

    def get_version(self) -> str | None:
        kuna = self._kuna_bin()
        if not kuna:
            return None
        try:
            p = subprocess.run(
                [kuna, "--version"], capture_output=True, text=True, timeout=30
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
            payload = self._run_decompile_all(binary_path)
        except Exception as e:  # noqa: BLE001
            _l.error("kuna-raw: discover failed on %s: %s", binary_path, e)
            return []
        text_range = common.elf_text_range(binary_path)
        out = [
            (str(r.get("name") or ""), int(r.get("address") or 0))
            for r in self._records(payload)
        ]
        out = [(n, a) for (n, a) in out if not common.should_skip_function(n, a, text_range)]
        return sorted(out, key=lambda x: x[1])

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a whole binary with kuna (one CLI invocation per binary)."""
        if not self.is_available():
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available "
                f"(kuna CLI not found; set $KUNA_BIN or add it to PATH)"
            )

        start = time.time()
        text_range = common.elf_text_range(binary_path)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        timed_out = False

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "kuna", "via": "raw"}
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

        # 1. One CLI invocation for the whole binary (load + analyze once).
        try:
            payload = self._run_decompile_all(binary_path)
        except subprocess.TimeoutExpired as e:
            timed_out = True
            _l.warning("kuna-raw timed out on %s: %s", binary_path, e)
            return self._error_result(binary_path, start, "timeout", timed_out=True)
        except Exception as e:  # noqa: BLE001
            _l.error("kuna-raw failed on %s: %s", binary_path, e)
            return self._error_result(binary_path, start, str(e))

        # 2. Index by name, filter to the benchmarkable + source-narrowed set
        #    (skip-set -> functions allowlist -> narrow_to_source), assemble.
        records = {str(r.get("name") or ""): r for r in self._records(payload)}
        enumerated = sorted(
            (
                (n, int(r.get("address") or 0))
                for n, r in records.items()
                if not common.should_skip_function(n, int(r.get("address") or 0), text_range)
            ),
            key=lambda x: x[1],
        )
        if functions is not None:
            requested = {n for (n, _a) in functions}
            enumerated = [(n, a) for (n, a) in enumerated if n in requested]
        enumerated = common.narrow_to_source(
            enumerated, function_names, backend="kuna", binary_name=binary_path.name
        )

        for func_name, file_addr in enumerated:
            fd = None
            try:
                fd = self._build_function(records[func_name], func_name, file_addr)
            except Exception as e:  # noqa: BLE001
                _l.debug("kuna-raw: assembling %s failed: %s", func_name, e)
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
    # kuna CLI plumbing
    #

    def _build_command(self, binary_path: Path) -> list[str]:
        kuna = self._kuna_bin()
        assert kuna is not None
        cmd = [kuna, "decompile-all", str(binary_path), "--json"]
        # Any kuna stage-model `--option NAME VALUE` flags passed through config.
        for key, value in (self.config.extra_options or {}).items():
            cmd += ["--option", str(key), str(value)]
        return cmd

    @staticmethod
    def _kill_group(p: subprocess.Popen) -> None:
        """SIGKILL kuna's whole process group (pgid == pid via start_new_session).

        Mirrors ``scripts/run_benchmark._kill_process_group``: a plain
        ``p.kill()`` (what ``subprocess.run(timeout=)`` does) kills only the
        direct child, letting a hung kuna ORPHAN and spin at 100% CPU forever.
        """
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
        """Per-binary timeout: ``$DECBENCH_KUNA_TIMEOUT`` (seconds) if set,
        else ``config.binary_timeout_seconds``."""
        env = os.environ.get("DECBENCH_KUNA_TIMEOUT")
        if env:
            try:
                return int(env)
            except ValueError:
                _l.warning("ignoring non-integer DECBENCH_KUNA_TIMEOUT=%r", env)
        return self.config.binary_timeout_seconds

    def _run_decompile_all(self, binary_path: Path) -> Any:
        """Run ``kuna decompile-all --json`` and parse the JSON document.

        Cached per (resolved) binary path so ``discover_functions`` followed by
        ``decompile_binary`` does not pay for two full loads.
        """
        key = str(binary_path)
        if key in self._payload_cache:
            return self._payload_cache[key]
        cmd = self._build_command(binary_path)
        _l.debug("kuna run: %s", " ".join(cmd))
        # start_new_session=True makes kuna lead its own process group so a
        # timeout (or any other failure) can SIGKILL the WHOLE tree. It also
        # means an outer harness killpg can no longer reach it — this backend
        # must own the kill on every exit path.
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
            # TimeoutExpired or ANY other exception: reap the group, then let
            # the exception propagate unchanged so callers behave identically.
            if p.poll() is None:
                self._kill_group(p)
        if p.returncode != 0 and not (stdout or "").strip():
            tail = (stderr or "")[-500:]
            raise RuntimeError(f"kuna exited {p.returncode}: {tail}")
        payload = json.loads(stdout)
        self._payload_cache[key] = payload
        return payload

    @staticmethod
    def _records(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            return list(payload.get("functions") or [])
        return payload if isinstance(payload, list) else []

    def _build_function(
        self, rec: dict[str, Any], name: str, file_addr: int
    ) -> FunctionDecompilation | None:
        code = rec.get("code")
        if not code:  # null (a per-function error) or empty -> failed
            return None
        return FunctionDecompilation(
            name=name,
            address=file_addr,
            decompiled_code=str(code),
            line_count=str(code).count("\n") + 1,
            line_mappings=[],  # no metric consumes these; kuna omits them
            variables=self._variables(rec),
            metadata=common.extract_metrics(str(code)),
        )

    @staticmethod
    def _variables(rec: dict[str, Any]) -> list[VariableInfo]:
        out: list[VariableInfo] = []
        for v in rec.get("variables") or []:
            kind = str(v.get("kind") or "stack")
            out.append(
                VariableInfo(
                    name=str(v.get("name") or ""),
                    type=str(v.get("type") or ""),
                    stack_offset=(
                        int(v["stack_offset"]) if v.get("stack_offset") is not None else None
                    ),
                    size=(int(v["size"]) if v.get("size") is not None else None),
                    kind="arg" if kind == "arg" else "stack",
                    arg_index=(
                        int(v["arg_index"]) if v.get("arg_index") is not None else None
                    ),
                )
            )
        return out

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
                extra={"error": err, "backend": "kuna", "via": "raw"},
            ),
        )
