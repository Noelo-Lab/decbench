"""Agentic Glaurung backend — decompiler + LLM enrichment, via ``glaurung explain``.

This is a **different category** from the ``codex`` / ``claude-code`` backends
(``decbench/decompilers/llm_dec.py``): those forbid using any decompiler and
reconstruct C by hand. This backend deliberately does the opposite — it runs
Glaurung's *own* decompiler and then its LLM re-render pass:

    native LLIR pseudocode → infer_function_signature → classify_function_role
        → rewrite_function_idiomatic  (idiomatic, source-faithful C)

which is exactly what ``glaurung explain <binary> --func <va> --format json``
produces (``python/glaurung/cli/commands/explain.py``). So this harness is thin
glue: one CLI call per target function, parse the rewritten ``source`` C, map it
to a :class:`FunctionDecompilation`. No new decompilation logic lives here.

One agentic CLI call per function is expensive, so — like the LLM backends — the
same two guards apply: the run driver's sample-set gate
(``DECBENCH_SAMPLESET_MANIFEST`` restricts each binary's target set), and a
per-binary ``max_funcs`` backstop (:data:`_DEFAULT_MAX_FUNCS`) so a mis-configured
run degrades to "a few calls per binary", never a whole-corpus fan-out.

Model selection is a version spec: ``-d glaurung-agentic@openai:gpt-5.4-mini``
pins the model as its own scoreboard column and forwards it to the ``explain``
subprocess via ``GLAURUNG_LLM_MODEL``. Requires an LLM API key in the child env
(``OPENAI_API_KEY`` for the default openai model, or ``ANTHROPIC_API_KEY``).

Locate the CLI via ``$GLAURUNG_BIN`` or ``glaurung`` on ``$PATH``.
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

_l = logging.getLogger(__name__)

# Per-binary hard cap on agent calls — the runaway backstop when the sample-set
# gate is missing. Override with DECBENCH_GLAURUNG_MAX_FUNCS or ``max_funcs``.
_DEFAULT_MAX_FUNCS = 8
_DEFAULT_TIMEOUT = 900  # per-function wall-clock (s)
_DEFAULT_MODEL = "openai:gpt-5.4-mini"


@register_decompiler("glaurung-agentic")
class GlaurungAgenticDecompiler(Decompiler):
    """Glaurung native decompile + LLM idiomatic-C rewrite, via ``glaurung explain``."""

    name = "glaurung-agentic"
    display_name = "Glaurung (agentic)"

    # --- location / config -------------------------------------------------

    @staticmethod
    def _glaurung_bin() -> str | None:
        env = os.environ.get("GLAURUNG_BIN")
        if env and Path(env).is_file():
            return env
        return shutil.which("glaurung")

    def _opt(self, key: str, env: str, default: Any) -> Any:
        s = self.config.extra_options or {}
        if key in s and s[key] not in (None, ""):
            return s[key]
        val = os.environ.get(env)
        return val if val not in (None, "") else default

    def _model(self) -> str:
        # A pinned spec (glaurung-agentic@openai:gpt-5.4-mini) is the model id.
        if self.requested_version:
            return str(self.requested_version)
        return str(self._opt("model", "GLAURUNG_LLM_MODEL", _DEFAULT_MODEL))

    def _max_funcs(self) -> int:
        try:
            return int(self._opt("max_funcs", "DECBENCH_GLAURUNG_MAX_FUNCS", _DEFAULT_MAX_FUNCS))
        except (TypeError, ValueError):
            return _DEFAULT_MAX_FUNCS

    def _timeout(self) -> int:
        try:
            return int(self._opt("timeout", "DECBENCH_GLAURUNG_LLM_TIMEOUT", _DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            return _DEFAULT_TIMEOUT

    def _fn_workers(self) -> int:
        try:
            return max(1, int(self._opt("fn_workers", "DECBENCH_GLAURUNG_FN_WORKERS", 1)))
        except (TypeError, ValueError):
            return 1

    # --- availability / version -------------------------------------------

    def is_available(self) -> bool:
        if self._glaurung_bin() is None:
            return False
        # `explain` needs an LLM key: OPENAI for the default openai model, or
        # ANTHROPIC for the fallback / an anthropic:* spec.
        return bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))

    def get_version(self) -> str | None:
        exe = self._glaurung_bin()
        model = self._model()
        if not exe:
            return None
        ver = ""
        try:
            p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
            out = (p.stdout or p.stderr or "").strip()
            m = re.search(r"(\d+\.\d+\.\d+\S*)", out)
            ver = m.group(1) if m else (out.splitlines()[0] if out else "")
        except Exception:  # noqa: BLE001
            ver = ""
        return f"{model} (glaurung {ver})" if ver else (model or None)

    # --- target selection --------------------------------------------------

    def _select_targets(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        function_names: set[int] | None,
    ) -> list[tuple[str, int]]:
        """(placeholder_name, address) work list.

        Priority: explicit ``functions`` > the driver's DWARF address set
        (``function_names``) > nothing. A stripped binary with no target set
        yields an empty list — the intended guard against an uncapped fan-out.
        """
        if functions:
            return [(n, int(a)) for n, a in functions]
        if function_names:
            return [(f"sub_{int(a):x}", int(a)) for a in sorted(function_names)]
        return []

    # --- decompile ---------------------------------------------------------

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
        **_: Any,
    ) -> DecompilationResult:
        binary_path = Path(binary_path)
        start = time.time()
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {
                "backend": "glaurung-agentic",
                "via": "explain",
                "model": self._model(),
                "slice_scoped": True,
            }
            if partial:
                extra["partial"] = True
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                timeout_occurred=False,
                failed_functions=list(failed),
                extra=extra,
            )

        def _dump() -> None:
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

        if not self.is_available():
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available (need the glaurung CLI "
                f"plus OPENAI_API_KEY or ANTHROPIC_API_KEY)"
            )

        targets = self._select_targets(binary_path, functions, function_names)
        cap = self._max_funcs()
        if len(targets) > cap:
            _l.warning(
                "glaurung-agentic: %d targets for %s exceeds max_funcs=%d; capping. "
                "Gate the run with DECBENCH_SAMPLESET_MANIFEST to avoid this.",
                len(targets),
                binary_path.name,
                cap,
            )
            targets = targets[:cap]

        if not targets:
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=_meta(partial=False),
                functions={},
                output_dir=output_dir,
            )

        workers = min(self._fn_workers(), len(targets))

        def _work(item: tuple[str, int]) -> tuple[str, int, str | None]:
            name, addr = item
            try:
                code = self._explain_one(binary_path, addr, output_dir)
            except Exception as e:  # noqa: BLE001
                _l.debug("glaurung-agentic: %s @ %#x failed: %s", name, addr, e)
                code = None
            return name, addr, code

        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(_work, targets))
        else:
            results = [_work(t) for t in targets]

        for name, addr, code in results:
            if code and code.strip():
                decompiled[name] = FunctionDecompilation(
                    name=name,
                    address=int(addr),
                    decompiled_code=code,
                    line_count=code.count("\n") + 1,
                    line_mappings=[],
                    variables=[],  # type_match parses the C signature text
                    metadata=common.extract_metrics(code),
                )
            else:
                failed.append(name)
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

    # --- one function ------------------------------------------------------

    def _explain_one(
        self, binary_path: Path, addr: int, output_dir: Path | None
    ) -> str | None:
        """Run ``glaurung explain --func <addr> --format json`` once; return the
        rewritten C (``c_prototype`` + ``source``), or ``None`` on failure."""
        exe = self._glaurung_bin()
        assert exe is not None
        cmd = [
            exe,
            "explain",
            str(binary_path),
            "--func",
            str(int(addr)),
            "--format",
            "json",
        ]
        env = dict(os.environ)
        env["GLAURUNG_LLM_MODEL"] = self._model()
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        try:
            stdout, stderr = p.communicate(timeout=self._timeout())
        finally:
            if p.poll() is None:
                self._kill_group(p)

        if self._save_traces() and output_dir is not None:
            self._write_trace(output_dir, addr, cmd, stdout, stderr)

        if not (stdout or "").strip():
            return None
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return None
        source = payload.get("source")
        if not source or not str(source).strip():
            return None
        proto = payload.get("c_prototype") or payload.get("prototype")
        source = str(source)
        # Prepend the recovered prototype as a leading comment if the rewrite did
        # not already open with a definition (helps the type_match signature scan).
        if proto and str(proto).strip() and "(" not in source.splitlines()[0]:
            source = f"// {str(proto).strip()}\n{source}"
        return source

    # --- plumbing ----------------------------------------------------------

    def _save_traces(self) -> bool:
        return str(self._opt("save_traces", "DECBENCH_GLAURUNG_SAVE_TRACES", "1")).lower() not in (
            "0",
            "false",
            "no",
        )

    def _write_trace(
        self, output_dir: Path, addr: int, cmd: list[str], stdout: str, stderr: str
    ) -> None:
        try:
            tdir = output_dir / "traces"
            tdir.mkdir(parents=True, exist_ok=True)
            (tdir / f"explain_{addr:#x}.md").write_text(
                f"# glaurung explain @ {addr:#x}\n\n"
                f"## command\n\n```\n{' '.join(cmd)}\n```\n\n"
                f"## stdout\n\n```json\n{stdout}\n```\n\n"
                f"## stderr\n\n```\n{stderr}\n```\n"
            )
        except Exception:  # noqa: BLE001 - traces are best-effort
            pass

    @staticmethod
    def _kill_group(p: subprocess.Popen) -> None:
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
