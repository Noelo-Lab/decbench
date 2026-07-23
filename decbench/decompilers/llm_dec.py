"""LLM / coding-agent decompiler backends (Codex, Claude Code, Kimi Code).

This family drives a **general coding agent** (OpenAI's ``codex`` CLI,
Anthropic's ``claude`` CLI, or Moonshot's ``kimi`` CLI) as a decompiler: for
each target function it hands
the agent the stripped binary and asks it to *manually* reconstruct the original
C source — the agent is explicitly **forbidden from using any decompiler** and
may only reach for simple disassemblers (``objdump``/``readelf``/``nm``/…). The
agent's C output is wrapped into the same :class:`DecompilationResult` contract
every other backend produces, so GED / type_match / byte_match score it exactly
like Ghidra or IDA.

Two things make this family different from the raw/dockerized backends and drive
the design:

* **Cost.** One agentic CLI invocation per function is expensive, so these
  backends are meant to run on the ``sample-set`` slice only. The run driver
  gates *which* functions reach the backend (``DECBENCH_SAMPLESET_MANIFEST`` in
  ``scripts/run_benchmark.py``), and the backend adds a belt-and-suspenders
  per-binary hard cap (:data:`_DEFAULT_MAX_FUNCS`) so a mis-configured run can
  never fan out across the whole corpus. See ``docs/LLM_DECOMPILERS.md``.
* **Auth.** The CLIs authenticate with the host user's own credentials
  (``~/.codex/auth.json`` / ``~/.claude/.credentials.json`` or
  ``ANTHROPIC_API_KEY``/``OPENAI_API_KEY``). Run on the host, the subprocess
  simply inherits them. Run inside the project container (config/env
  ``docker_image``), the wrapper bind-mounts those token dirs and forwards the
  key env vars, so the container "inherits the token from outside".

The addresses the driver passes are DWARF ``low_pc`` values (ELF-file space) on a
*stripped* binary, so the backend labels each function ``sub_<addr>`` and stores
the DWARF address; ``run_benchmark._relabel_to_dwarf`` renames the placeholder to
the real symbol for evaluation, exactly as it does for angr/Ghidra.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.decompilers.spec import version_settings
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

_l = logging.getLogger(__name__)

# Per-binary hard cap on how many functions a single decompile call will send to
# the agent. The sample-set takes at most a handful of functions per binary, so
# this is a runaway guard: even if the driver's sample-set gate is forgotten and
# the backend is pointed at a gnulib-heavy binary with hundreds of source
# functions, it will never issue more than this many (very expensive) agent
# calls for one binary. Override with DECBENCH_LLM_MAX_FUNCS or the ``max_funcs``
# config key.
_DEFAULT_MAX_FUNCS = 8

# Per-function wall-clock budget for one agent invocation (seconds). Manual
# decompilation of one function — read disassembly, reason, write C — is slow;
# the run driver's per-binary budget must comfortably exceed this times the
# per-binary function count. Override with DECBENCH_LLM_TIMEOUT or ``timeout``.
_DEFAULT_TIMEOUT = 900

# The single-function C output file the agent is told to write, inside its
# per-function working directory. Reading a known file is far more reliable than
# scraping the agent's chat transcript; stdout is only the fallback.
_OUTFILE = "decompiled.c"


# ---------------------------------------------------------------------------
# The shared decompilation prompt (the "common prompt for LLM systems").
# ---------------------------------------------------------------------------
#: The task/system instruction shared by every LLM decompiler backend. It states
#: the goal (reconstruct original-source-faithful C), the hard tool policy (no
#: decompilers; simple disassemblers like objdump only), the method, and the
#: file-based output contract. Per-function specifics (binary, address, arch, a
#: disassembly hint, the output path) are appended by :meth:`_build_prompt`.
LLM_DECOMPILE_PROMPT = """\
You are an expert reverse engineer performing MANUAL decompilation by hand.

GOAL
Given a compiled binary, reconstruct the original C source code for ONE target
function. Make the C as correct and as close to the original human-written
source as you can: recover the real control flow, argument and return types,
local variables and their roles, struct/array accesses, and calls to other
functions and to libc.

HARD TOOL POLICY (this is the whole point of the exercise — follow it exactly)
- You are BANNED from using any decompiler or anything that emits C / pseudo-C.
  This includes Ghidra, IDA / Hex-Rays, Binary Ninja, angr, RetDec, Reko,
  r2dec / r2ghidra / radare2's `pdc`/`pdg`, dewolf, and any online or local
  "AI decompiler". Do NOT install, download, or invoke any of them.
- You MAY use only simple, non-decompiling binary inspection tools:
  `objdump`, `readelf`, `nm`, `strings`, `xxd` / `od`, `file`, `size`, `c++filt`.
  Read the raw assembly yourself and reason about it; hand-write the C.

METHOD
- Disassemble the target function (e.g. `objdump -d <binary>`), locate it by its
  virtual address, and read the assembly instruction by instruction.
- Recover the calling convention (argument registers/stack, return register) to
  infer the function signature and argument types.
- Rebuild structured control flow: express loops and branches as idiomatic C
  (`for` / `while` / `if` / `else` / `switch`), NOT as a literal transliteration
  of jumps. Only use `goto` when the control flow genuinely cannot be expressed
  structurally.
- Give variables meaningful C types inferred from how they are used (widths,
  pointer dereferences, sign, struct field offsets). Use real libc prototypes
  for resolved library calls; give plausible types to unknown externs.
- Prefer the code a competent human would have written over an assembly-shaped
  transliteration, while staying faithful to the observed behavior.

OUTPUT CONTRACT
- Write ONLY the reconstructed C for the single target function (plus any
  local typedef/struct/enum declarations it needs) to the output file named
  below.
- The file must contain EXACTLY ONE top-level definition of the target function.
- No markdown fences, no commentary, no analysis prose inside the file — just
  compilable C.
"""


def _creds_present(*candidates: Path) -> bool:
    """Whether any of the credential files exists (cheap, no network)."""
    return any(p.is_file() for p in candidates)


# Matches a function *definition* header: ``name(params) {``. Anchored on the
# name-before-parens rather than the return type, so a preceding prose line
# cannot bleed into the match (the name/params/brace are the reliable part; the
# return type is recovered by extending to the start of the name's line).
_FUNC_HEADER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")


def _find_func_span(text: str) -> tuple[int, int, str] | None:
    """Locate the first C function definition: ``(start, end, name)`` or ``None``.

    ``start`` is the beginning of the line holding the function name (so the
    return type on that line is included); ``end`` is just past the matching
    closing brace; ``name`` is the function identifier.
    """
    m = _FUNC_HEADER_RE.search(text)
    if not m:
        return None
    brace = text.index("{", m.end() - 1)
    line_start = text.rfind("\n", 0, m.start()) + 1
    depth = 0
    for i in range(brace, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                return line_start, i + 1, m.group(1)
    return None


def _extract_c(text: str) -> str | None:
    """Best-effort recovery of a C function body from an agent's stdout.

    Only used when the agent did not write the output file. Prefers a fenced
    ```c code block; falls back to the first brace-balanced function definition.
    """
    if not text:
        return None
    fence = re.search(r"```(?:c|cpp|C)?\s*\n(.*?)```", text, re.DOTALL)
    if fence:
        body = fence.group(1).strip()
        if "{" in body:
            return body
    span = _find_func_span(text)
    if span is None:
        return None
    start, end, _ = span
    return text[start:end]


def _func_ident_in_code(code: str) -> str | None:
    """The identifier of the first function *definition* in ``code``."""
    span = _find_func_span(code)
    return span[2] if span else None


def _rename_func(code: str, target: str) -> str:
    """Rename the reconstructed function's identifier to ``target``.

    The run driver relabels a stripped-binary decompilation by address, rewriting
    the name in BOTH the code and the result dict — which only works if the
    ``FunctionDecompilation.name`` matches the identifier in ``decompiled_code``.
    We therefore force both to the ``sub_<addr>`` placeholder here (mirrors
    ``dockerized.R2DecDecompiler._make_function``).
    """
    ident = _func_ident_in_code(code)
    if ident and ident != target:
        code = re.sub(r"\b" + re.escape(ident) + r"\b", target, code)
    return code


def _disasm_hint(binary_path: Path, addr: int, max_bytes: int = 640) -> str:
    """A short linear disassembly starting at ``addr`` to seed the prompt.

    Reads raw ``.text`` bytes at the function's virtual address (the binary is
    stripped, so there is no symbol/DWARF range) and linearly disassembles with
    capstone, stopping at a ``ret`` followed by padding or after ~max_bytes. This
    is a *hint*; the agent is expected to run objdump itself for the full picture.
    Returns an empty string on any failure (arch not supported, capstone absent).
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            if text is None:
                return ""
            sh_addr = text["sh_addr"]
            data = text.data()
        off = addr - sh_addr
        if off < 0 or off >= len(data):
            return ""
        blob = data[off : off + max_bytes]
    except Exception:  # noqa: BLE001
        return ""

    try:
        import capstone

        from decbench.utils import binfmt

        fmt = binfmt.detect(binary_path)
        if fmt is None:
            return ""
        # ARM: DWARF low_pc is even, but a Thumb function's real entry has the
        # T-bit set; disassemble as Thumb when the address is odd.
        thumb = fmt.arch == "arm" and bool(addr & 1)
        am = binfmt.capstone_arch_mode(fmt, thumb=thumb)
        if am is None:
            return ""
        md = capstone.Cs(*am)
        lines: list[str] = []
        for insn in md.disasm(blob, addr & ~1 if thumb else addr):
            lines.append(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".rstrip())
            if insn.mnemonic in ("ret", "retq", "bx", "pop") and len(lines) > 3:
                # Stop shortly after a plausible epilogue return.
                break
            if len(lines) >= 80:
                break
        return "\n".join(lines)
    except Exception:  # noqa: BLE001
        return ""


class _AgentDecompiler(Decompiler):
    """Shared driver for CLI coding-agent decompilers.

    Subclasses set ``name`` / ``display_name`` / ``cli`` / ``default_model``,
    declare their credential files, and build the concrete CLI argv. Everything
    else — target selection, the cost cap, the per-function agent loop, output
    parsing, checkpointing, and result assembly — lives here.
    """

    # Subclass contract.
    cli: str = ""  # the CLI binary name (must be on PATH)
    default_model: str = ""  # model id used when config/env do not override
    #: Credential files (relative to $HOME) that indicate the CLI is logged in.
    cred_files: tuple[str, ...] = ()
    #: Env vars that also count as valid credentials (e.g. an API key).
    cred_env: tuple[str, ...] = ()

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._version_cache: str | None = None

    # --- configuration -----------------------------------------------------

    def _settings(self) -> dict[str, Any]:
        """Per-version config (``decompilers.toml``), with a ``default`` fallback."""
        s = version_settings(self.name, self.requested_version)
        if not s and self.requested_version is None:
            s = version_settings(self.name, "default")
        # extra_options (from DecompilerConfig) win over the TOML file.
        merged = dict(s)
        merged.update(self.config.extra_options or {})
        return merged

    def _opt(self, key: str, env: str, default: Any) -> Any:
        """Resolve a setting: config file/extra_options > env var > default."""
        s = self._settings()
        if key in s and s[key] not in (None, ""):
            return s[key]
        val = os.environ.get(env)
        return val if val not in (None, "") else default

    def _model(self) -> str:
        # A pinned spec (codex@gpt-5.6) makes the version label the model id.
        if self.requested_version:
            return str(self.requested_version)
        return str(self._opt("model", "DECBENCH_LLM_MODEL", self.default_model))

    def _max_funcs(self) -> int:
        try:
            return int(self._opt("max_funcs", "DECBENCH_LLM_MAX_FUNCS", _DEFAULT_MAX_FUNCS))
        except (TypeError, ValueError):
            return _DEFAULT_MAX_FUNCS

    def _timeout(self) -> int:
        try:
            return int(self._opt("timeout", "DECBENCH_LLM_TIMEOUT", _DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            return _DEFAULT_TIMEOUT

    def _fn_workers(self) -> int:
        """How many of a binary's functions to decompile concurrently (>=1)."""
        try:
            return max(1, int(self._opt("fn_workers", "DECBENCH_LLM_FN_WORKERS", 1)))
        except (TypeError, ValueError):
            return 1

    def _docker_image(self) -> str | None:
        img = self._opt("docker_image", "DECBENCH_LLM_DOCKER_IMAGE", "")
        return str(img) or None

    # --- availability / version -------------------------------------------

    def is_available(self) -> bool:
        if shutil.which(self.cli) is None:
            return False
        home = Path.home()
        if _creds_present(*[home / c for c in self.cred_files]):
            return True
        return any(os.environ.get(e) for e in self.cred_env)

    def get_version(self) -> str | None:
        if self._version_cache is not None:
            return self._version_cache or None
        ver = ""
        try:
            proc = subprocess.run(
                [self.cli, "--version"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            out = (proc.stdout or proc.stderr or "").strip().splitlines()
            if out:
                # e.g. "codex-cli 0.144.1" / "2.1.215 (Claude Code)"
                toks = out[0].split()
                ver = next((t for t in toks if any(c.isdigit() for c in t)), out[0])
        except Exception:  # noqa: BLE001
            ver = ""
        self._version_cache = ver
        # Report the model too, so scoreboard versions distinguish gpt-5.6 etc.
        model = self._model()
        return f"{model} ({ver})" if ver else (model or None)

    # --- subclass hooks ----------------------------------------------------

    def _agent_argv(self, workdir: Path, prompt: str, model: str) -> list[str]:
        """Return the CLI argv (run with ``cwd=workdir``). Subclass implements."""
        raise NotImplementedError

    def _agent_env(self) -> dict[str, str]:
        """Environment for the agent subprocess. Subclass may extend."""
        return dict(os.environ)

    # --- the decompile entrypoint -----------------------------------------

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
        started = time.time()
        targets = self._select_targets(binary_path, functions, function_names)

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                # slice_scoped: this backend only ever attempts an explicit
                # target slice (the sample-set manifest); functions outside it
                # were never attempted and must not be stamped decompiled=False.
                extra={
                    "backend": self.name,
                    "via": "llm-agent",
                    "model": self._model(),
                    "slice_scoped": True,
                },
            ),
            output_dir=output_dir,
        )
        if not targets:
            _l.info(
                "llm/%s: no target functions for %s (nothing to do)", self.name, binary_path.name
            )
            return result

        cap = self._max_funcs()
        if len(targets) > cap:
            _l.warning(
                "llm/%s: %d target functions for %s exceeds the per-binary cap "
                "(%d) — truncating to bound cost. Gate the run to sample-set "
                "(DECBENCH_SAMPLESET_MANIFEST) to avoid this.",
                self.name,
                len(targets),
                binary_path.name,
                cap,
            )
            targets = targets[:cap]

        failed: list[str] = []
        lock = threading.Lock()

        def _record(name: str, addr: int, code: str | None) -> None:
            with lock:
                if code:
                    result.functions[name] = FunctionDecompilation(
                        name=name,
                        address=addr,
                        decompiled_code=code,
                        line_count=code.count("\n") + 1,
                        metadata=common.extract_metrics(code),
                    )
                else:
                    failed.append(name)
                # Checkpoint partials so a hard-timeout kill still credits finished work.
                result.decompiler.failed_functions = list(failed)
                result.decompiler.total_time_seconds = time.time() - started
                common.dump_progress(progress_path, result)

        def _one(name: str, addr: int) -> None:
            try:
                code = self._decompile_one(binary_path, name, addr, output_dir)
            except Exception as e:  # noqa: BLE001
                _l.warning("llm/%s: %s @ 0x%x failed: %s", self.name, name, addr, e)
                code = None
            _record(name, addr, code)

        # A binary's sampled functions are independent agent calls, so run them
        # concurrently — a single-binary/multi-function project otherwise decompiles
        # one function at a time while the run's other workers sit idle. Pool size
        # via DECBENCH_LLM_FN_WORKERS / the ``fn_workers`` config key.
        workers = min(self._fn_workers(), len(targets))
        if workers <= 1:
            for name, addr in targets:
                _one(name, addr)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(lambda t: _one(*t), targets))

        result.decompiler.failed_functions = failed
        result.decompiler.total_time_seconds = time.time() - started
        return result

    # --- helpers -----------------------------------------------------------

    def _select_targets(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        function_names: set[int] | None,
    ) -> list[tuple[str, int]]:
        """Resolve the (placeholder_name, address) work list.

        Priority: explicit ``functions`` > the driver's DWARF address set
        (``function_names``) > ELF symbol enumeration (only useful on a
        non-stripped binary; empty on a stripped one — which is the safe default,
        since these backends must never fan out across a whole binary uncapped).
        """
        if functions:
            return [(n, int(a)) for n, a in functions]
        if function_names:
            return [(f"sub_{int(a):x}", int(a)) for a in sorted(function_names)]
        # No filter given (e.g. a bare `decbench run`). Enumerate real symbols in
        # .text; a stripped binary yields nothing, which is the intended guard.
        try:
            from decbench.decompilers.dockerized import elf_function_symbols

            text_range = common.elf_text_range(binary_path)
            syms = [
                (n, a)
                for n, a in elf_function_symbols(binary_path)
                if not common.should_skip_function(n, a, text_range)
            ]
            return syms
        except Exception:  # noqa: BLE001
            return []

    def _decompile_one(
        self, binary_path: Path, name: str, addr: int, output_dir: Path | None = None
    ) -> str | None:
        """Run the agent once for one function and return its C (or ``None``).

        When trace-saving is on (default; disable with ``DECBENCH_LLM_SAVE_TRACES=0``)
        and ``output_dir`` is known, the agent's full transcript — prompt, stdout,
        the reconstructed C, and (for claude) the CLI's own session JSONL with every
        objdump/tool call — is written to ``<output_dir>/traces/`` linked to this
        exact function.
        """
        t0 = time.time()
        with tempfile.TemporaryDirectory(prefix=f"llmdec_{self.name}_") as tmp:
            workdir = Path(tmp)
            # Copy the (stripped) binary in under a NEUTRAL name so the agent gets
            # no identity signal from the filename. The original name (e.g. `grep`,
            # `gzip`, `nuttx`) would tell an LLM exactly which open-source program
            # it is looking at and let it recall the source from memory instead of
            # reverse-engineering — an advantage a mechanical decompiler never gets.
            local = workdir / "target.bin"
            shutil.copy2(binary_path, local)
            outfile = workdir / _OUTFILE
            prompt = self._build_prompt(binary_path, local.name, name, addr, outfile.name)

            argv, run_kwargs = self._invocation(workdir, prompt, local)
            stdout = ""
            timed_out = False
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    stdin=subprocess.DEVNULL,
                    timeout=self._timeout(),
                    **run_kwargs,
                )
                stdout = (proc.stdout or "") + "\n" + (proc.stderr or "")
            except subprocess.TimeoutExpired as e:
                stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
                timed_out = True
                _l.warning("llm/%s: agent timed out on %s @ 0x%x", self.name, name, addr)

            code = None
            if outfile.is_file():
                text = outfile.read_text(errors="replace").strip()
                code = text or None
            if not code:
                code = _extract_c(stdout)
            final = _rename_func(_sanitize(code), name) if code else None
            # Capture the trace BEFORE the temp dir (and the agent's session file
            # under it, for claude) is torn down.
            self._save_trace(
                output_dir,
                binary_path,
                name,
                addr,
                workdir,
                prompt,
                stdout,
                final,
                elapsed=time.time() - t0,
                timed_out=timed_out,
            )
            return final

    def _traces_enabled(self) -> bool:
        return str(self._opt("save_traces", "DECBENCH_LLM_SAVE_TRACES", "1")).lower() not in (
            "0",
            "false",
            "no",
        )

    def _save_trace(
        self,
        output_dir: Path | None,
        binary_path: Path,
        name: str,
        addr: int,
        workdir: Path,
        prompt: str,
        transcript: str,
        code: str | None,
        elapsed: float,
        timed_out: bool,
    ) -> None:
        """Persist the agent's per-function trace.

        Into ``$DECBENCH_LLM_TRACE_DIR/<decompiler>/`` when that is set (a single
        collected folder), else ``<output_dir>/traces/``. Writes the prompt +
        transcript + reconstructed C as ``.md``, plus the CLI's OWN full session log
        (every objdump/tool call): the Claude session JSONL or the Codex rollout.
        """
        if not self._traces_enabled():
            return
        root = self._opt("trace_dir", "DECBENCH_LLM_TRACE_DIR", "")
        if root:
            trace_dir = Path(root) / self.id.replace("@", "-")
        elif output_dir is not None:
            trace_dir = Path(output_dir) / "traces"
        else:
            return
        try:
            trace_dir.mkdir(parents=True, exist_ok=True)
            label = self._trace_label(binary_path, name, addr)
            status = "TIMEOUT" if timed_out else ("ok" if code else "FAILED")
            body = (
                f"# {self.id} trace — {label}\n\n"
                f"- model: {self._model()}\n"
                f"- binary given to agent: target.bin (original: {binary_path.stem})\n"
                f"- status: {status}\n"
                f"- elapsed: {elapsed:.0f}s\n\n"
                f"## Prompt\n\n```\n{prompt}\n```\n\n"
                f"## Agent transcript (stdout/stderr)\n\n```\n{transcript.strip()}\n```\n\n"
                f"## Reconstructed C\n\n```c\n{code or '(none — failed)'}\n```\n"
            )
            (trace_dir / f"{label}.md").write_text(body)
            # The CLI's own session log carries every shell command it ran (the
            # authoritative record for auditing tool use). claude: session JSONL
            # under its config; codex: the rollout named by the session id.
            self._copy_session_jsonl(workdir, transcript, trace_dir / f"{label}.session.jsonl")
        except Exception as e:  # noqa: BLE001 - tracing must never break a run
            _l.debug("llm/%s: trace save failed for %s: %s", self.name, name, e)

    @staticmethod
    def _trace_label(binary_path: Path, name: str, addr: int) -> str:
        """``<opt>__<project>__<stem>__<func>_0x<addr>`` from the results-tree path."""
        parts = binary_path.parts
        opt = proj = ""
        if "stripped" in parts:
            i = parts.index("stripped")
            if i >= 2:
                opt, proj = parts[i - 2], parts[i - 1]
        prefix = f"{opt}__{proj}__" if proj else ""
        return f"{prefix}{binary_path.stem}__{name}_0x{addr:x}"

    def _copy_session_jsonl(self, workdir: Path, transcript: str, dest: Path) -> None:
        """Copy the CLI's own session JSONL for this call (subclass hook)."""
        return

    def _invocation(self, workdir: Path, prompt: str, local_binary: Path) -> tuple[list[str], dict]:
        """Build (argv, subprocess-kwargs), optionally wrapping in ``docker run``.

        Host mode (default): run the CLI directly with ``cwd=workdir``; it inherits
        the host user's credentials. Container mode (``docker_image`` configured):
        wrap in ``docker run`` that bind-mounts the workdir and the host token
        dirs read-only and forwards the key env vars, so a CLI inside the
        container "inherits the token from outside".
        """
        model = self._model()
        argv = self._agent_argv(workdir, prompt, model)
        env = self._agent_env()
        image = self._docker_image()
        if not image:
            return argv, {"cwd": str(workdir), "env": env}

        home = Path.home()
        docker = [
            shutil.which("docker") or "docker",
            "run",
            "--rm",
            "-v",
            f"{workdir.resolve()}:/work",
            "-w",
            "/work",
        ]
        # Mount whatever host credential dirs exist, read-only.
        token_dirs = (
            (home / ".codex", "/root/.codex"),
            (home / ".claude", "/root/.claude"),
            (
                Path(os.environ.get("KIMI_CODE_HOME") or home / ".kimi-code"),
                "/root/.kimi-code",
            ),
        )
        for host_dir, cont_dir in token_dirs:
            if host_dir.is_dir():
                docker += ["-v", f"{host_dir}:{cont_dir}:ro"]
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            if os.environ.get(key):
                docker += ["-e", key]
        docker += [
            "-e",
            "CODEX_HOME=/root/.codex",
            "-e",
            "KIMI_CODE_HOME=/root/.kimi-code",
            "-e",
            "HOME=/root",
            image,
        ]
        # Inside the container the workdir is /work, so rebuild the argv against it.
        argv = self._agent_argv(Path("/work"), prompt, model)
        return docker + argv, {"env": env}

    def _build_prompt(
        self, binary_path: Path, local_name: str, name: str, addr: int, outfile: str
    ) -> str:
        arch = "unknown"
        try:
            from decbench.utils import binfmt

            fmt = binfmt.detect(binary_path)
            arch = getattr(fmt, "arch", None) or "unknown"
        except Exception:  # noqa: BLE001
            pass
        hint = _disasm_hint(binary_path, addr)
        hint_block = ""
        if hint:
            hint_block = (
                "\nDISASSEMBLY HINT (linear from the entry; run objdump yourself "
                "for the authoritative full listing):\n" + hint + "\n"
            )
        return (
            f"{LLM_DECOMPILE_PROMPT}\n"
            f"TARGET\n"
            f"- Binary (in your working directory): ./{local_name}\n"
            f"- Architecture: {arch}\n"
            f"- The binary is STRIPPED, so the target function has no symbol name. "
            f"Identify it by its entry virtual address: 0x{addr:x}.\n"
            f"- Name the reconstructed function `{name}` in your C output.\n"
            f"{hint_block}"
            f"\nWrite the reconstructed C to the file `{outfile}` in your working "
            f"directory. When finished, make sure `{outfile}` exists and contains "
            f"only the C code (one definition of `{name}`).\n"
        )


def _sanitize(code: str) -> str:
    """Strip stray markdown fences an agent may leave around the C body."""
    code = code.strip()
    if code.startswith("```"):
        code = re.sub(r"^```[a-zA-Z]*\n", "", code)
        code = re.sub(r"\n```\s*$", "", code)
    return code.strip() + "\n"


@register_decompiler("codex")
class CodexDecompiler(_AgentDecompiler):
    """OpenAI Codex CLI driven as a manual decompiler (default model gpt-5.6)."""

    name = "codex"
    display_name = "OpenAI Codex CLI"
    cli = "codex"
    # ``gpt-5.6-sol`` is the gpt-5.6 variant a ChatGPT-account login exposes to
    # Codex (bare ``gpt-5.6`` / ``gpt-5.6-codex`` are rejected there with a 400).
    # Override per config/spec for an API-key login that allows other ids.
    default_model = "gpt-5.6-sol"
    cred_files = (".codex/auth.json",)
    cred_env = ("OPENAI_API_KEY",)

    def _agent_argv(self, workdir: Path, prompt: str, model: str) -> list[str]:
        argv = [
            self.cli,
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "-C",
            str(workdir),
        ]
        if model:
            argv += ["-m", model]
        argv.append(prompt)
        return argv

    def _agent_env(self) -> dict[str, str]:
        env = dict(os.environ)
        # Run under an ISOLATED CODEX_HOME whose skills/ dir is empty, so the
        # `decompiler` skill (which drives IDA/Ghidra/Binary Ninja via DecLib) is
        # not available — the LLM cannot fall back to a real decompiler even if it
        # wanted to. Auth (auth.json) + config.toml are synced from ~/.codex.
        env["CODEX_HOME"] = str(self._isolated_codex_home())
        return env

    def _isolated_codex_home(self) -> Path:
        """A decbench-owned CODEX_HOME with no skills (enforces the decompiler ban)."""
        import contextlib

        override = self._opt("codex_home", "DECBENCH_CODEX_HOME", "")
        home = Path(override) if override else Path.home() / ".cache" / "decbench" / "codex-home"
        home.mkdir(parents=True, exist_ok=True)
        (home / "skills").mkdir(exist_ok=True)  # empty -> no `decompiler` skill
        src = Path.home() / ".codex"
        for fn in ("auth.json", "config.toml"):
            s, d = src / fn, home / fn
            # Sync from ~/.codex only when it is newer, so codex's own in-place
            # token refresh (into the isolated auth.json) is not clobbered.
            if s.is_file() and (not d.exists() or s.stat().st_mtime > d.stat().st_mtime):
                with contextlib.suppress(Exception):
                    shutil.copy2(s, d)
        return home

    def _copy_session_jsonl(self, workdir: Path, transcript: str, dest: Path) -> None:
        """Copy codex's rollout JSONL (all shell commands) — found by session id."""
        try:
            m = re.search(r"session id:\s*([0-9a-f-]{36})", transcript)
            if not m:
                return
            sid = m.group(1)
            home = self._isolated_codex_home()
            rolls = list((home / "sessions").glob(f"**/*{sid}*.jsonl"))
            if not rolls:
                rolls = list((Path.home() / ".codex" / "sessions").glob(f"**/*{sid}*.jsonl"))
            if rolls:
                shutil.copy2(rolls[0], dest)
        except Exception:  # noqa: BLE001
            pass


@register_decompiler("claude-code")
class ClaudeCodeDecompiler(_AgentDecompiler):
    """Anthropic Claude Code CLI driven as a manual decompiler (default opus-4.8)."""

    name = "claude-code"
    display_name = "Claude Code"
    cli = "claude"
    default_model = "claude-opus-4-8"
    cred_files = (".claude/.credentials.json",)
    cred_env = ("ANTHROPIC_API_KEY",)

    def _agent_argv(self, workdir: Path, prompt: str, model: str) -> list[str]:
        argv = [
            self.cli,
            "-p",
            prompt,
            "--output-format",
            "text",
            # Let the agent run objdump and write the output file without prompts.
            "--dangerously-skip-permissions",
            # Disable ALL skills so the `decompiler` skill (which drives real
            # decompilers) is unavailable — enforces the decompiler ban.
            "--disable-slash-commands",
            "--add-dir",
            str(workdir),
        ]
        if model:
            argv += ["--model", model]
        return argv

    def _agent_env(self) -> dict[str, str]:
        env = super()._agent_env()
        # If the benchmark is launched from *inside* a Claude Code session, the
        # `CLAUDE_CODE_*` / bridge / session env vars leak into a nested `claude`
        # subprocess, which then tries to reattach to the parent session's daemon
        # and hangs indefinitely. Strip them so the nested CLI starts as an
        # independent instance. (Auth via ANTHROPIC_API_KEY / ~/.claude is kept.)
        for k in list(env):
            if k.startswith("CLAUDE_CODE_") or k in ("CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT"):
                env.pop(k, None)
        # Point the nested CLI at an ISOLATED config dir so it uses its own
        # daemon/session state and can never contend with (or be blocked by) an
        # interactive Claude Code session running as the same user. Override the
        # location with DECBENCH_CLAUDE_CONFIG_DIR.
        cfg = self._isolated_config_dir()
        env["CLAUDE_CONFIG_DIR"] = str(cfg)
        # Prefer the subscription OAuth login (the copied credentials) over
        # ANTHROPIC_API_KEY: a set API key SHADOWS the OAuth login, and here that
        # path was pathologically slow (a trivial `-p` call took >150s vs ~3s on
        # OAuth). So drop the key when OAuth credentials are present. Force the
        # API-key path instead with DECBENCH_CLAUDE_USE_API_KEY=1.
        if (cfg / ".credentials.json").is_file() and not os.environ.get(
            "DECBENCH_CLAUDE_USE_API_KEY"
        ):
            env.pop("ANTHROPIC_API_KEY", None)
        return env

    def _isolated_config_dir(self) -> Path:
        """A decbench-owned Claude config dir, kept in sync with host credentials.

        The OAuth token in ``~/.claude/.credentials.json`` is refreshed (and its
        refresh token *rotated*) over time, so a one-time copy goes stale and every
        later ``claude`` call fails with "OAuth session expired and could not be
        refreshed". We therefore re-sync the credentials from the live host file on
        every use (atomically), so each call reads a currently-valid access token
        and never needs to refresh with a rotated-out token.
        """
        import contextlib

        override = self._opt("claude_config_dir", "DECBENCH_CLAUDE_CONFIG_DIR", "")
        cfg = Path(override) if override else Path.home() / ".cache" / "decbench" / "claude-config"
        cfg.mkdir(parents=True, exist_ok=True)
        creds = Path.home() / ".claude" / ".credentials.json"
        dst = cfg / ".credentials.json"
        if creds.is_file():
            with contextlib.suppress(Exception):
                tmp = dst.with_suffix(".json.tmp")
                shutil.copy2(creds, tmp)
                tmp.replace(dst)  # atomic — no torn read for a concurrent claude
        return cfg

    def _copy_session_jsonl(self, workdir: Path, transcript: str, dest: Path) -> None:
        """Copy claude's session JSONL for this call (the full tool-call trace).

        Claude stores it under ``<config>/projects/<sanitised-cwd>/<uuid>.jsonl``,
        where the project dir name is the working directory with every
        non-alphanumeric char replaced by ``-``.
        """
        try:
            slug = re.sub(r"[^a-zA-Z0-9]", "-", str(workdir))
            proj = self._isolated_config_dir() / "projects" / slug
            sessions = sorted(proj.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
            if sessions:
                shutil.copy2(sessions[-1], dest)
        except Exception:  # noqa: BLE001
            pass


@register_decompiler("kimi-code")
class KimiCodeDecompiler(_AgentDecompiler):
    """Moonshot Kimi Code CLI driven as a manual decompiler (default model k3)."""

    name = "kimi-code"
    display_name = "Kimi Code"
    cli = "kimi"
    # ``kimi-code/k3`` is the Kimi K3 model alias a Kimi Code OAuth (membership)
    # login exposes; such logins also carry ``kimi-code/kimi-for-coding``
    # (-highspeed). Pin via spec/config, e.g. ``-d kimi-code@kimi-code/k3``.
    default_model = "kimi-code/k3"
    # Kimi Code reads NO credential from the shell environment (an exported
    # ``KIMI_API_KEY`` is ignored): auth is the OAuth store under
    # ``$KIMI_CODE_HOME/credentials/`` or an ``api_key`` in ``config.toml``. The
    # single env channel it honors is the ``KIMI_MODEL_*`` family (synthesized
    # provider) — all three are handled in is_available().
    cred_files = ()
    cred_env = ()

    @staticmethod
    def _real_home() -> Path:
        """The user's live Kimi Code home (``KIMI_CODE_HOME`` or ``~/.kimi-code``)."""
        env = os.environ.get("KIMI_CODE_HOME")
        return Path(env) if env else Path.home() / ".kimi-code"

    def is_available(self) -> bool:
        if shutil.which(self.cli) is None:
            return False
        home = self._real_home()
        creds = home / "credentials"
        if creds.is_dir() and any(creds.glob("*.json")):
            return True
        # The env-synthesized provider — the only credential channel read from env.
        if os.environ.get("KIMI_MODEL_NAME") and os.environ.get("KIMI_MODEL_API_KEY"):
            return True
        # An API-key provider written into config.toml ([providers.*] api_key /
        # [providers.*.env] KIMI_API_KEY). Presence check only; never logged.
        cfg = home / "config.toml"
        return cfg.is_file() and "api_key" in cfg.read_text(errors="replace")

    def _agent_argv(self, workdir: Path, prompt: str, model: str) -> list[str]:
        argv = [
            self.cli,
            "-p",
            prompt,
            "--output-format",
            "text",
            # Point skill discovery at an EMPTY directory: --skills-dir replaces
            # the auto-discovered user and project skill dirs for this launch,
            # so a `decompiler` skill (which drives real decompilers) cannot
            # load. ``-p`` already runs under the auto permission policy (no
            # approval prompts) — the kimi equivalent of claude's
            # --dangerously-skip-permissions.
            "--skills-dir",
            str(self._empty_skills_dir()),
        ]
        if model:
            argv += ["-m", model]
        return argv

    def _agent_env(self) -> dict[str, str]:
        env = dict(os.environ)
        # Run under an ISOLATED KIMI_CODE_HOME so benchmark calls never touch
        # the user's live sessions/state; credentials + config.toml are synced
        # from ~/.kimi-code, and its skills/ dir stays empty as
        # defense-in-depth behind --skills-dir.
        env["KIMI_CODE_HOME"] = str(self._isolated_kimi_home())
        return env

    def _isolated_kimi_home(self) -> Path:
        """A decbench-owned KIMI_CODE_HOME: no skills, synced auth + config."""
        import contextlib

        override = self._opt("kimi_code_home", "DECBENCH_KIMI_CODE_HOME", "")
        home = (
            Path(override) if override else Path.home() / ".cache" / "decbench" / "kimi-code-home"
        )
        home.mkdir(parents=True, exist_ok=True)
        (home / "skills").mkdir(exist_ok=True)  # empty -> no Kimi-specific user skills
        (home / "no-skills").mkdir(exist_ok=True)  # the --skills-dir target
        src = self._real_home()
        # Sync config.toml (providers/models) and the OAuth credential store
        # from ~/.kimi-code only when the host copy is newer, so kimi's own
        # in-place token refresh (into the isolated copies) is not clobbered.
        s, d = src / "config.toml", home / "config.toml"
        if s.is_file() and (not d.exists() or s.stat().st_mtime > d.stat().st_mtime):
            with contextlib.suppress(Exception):
                shutil.copy2(s, d)
        src_creds = src / "credentials"
        if src_creds.is_dir():
            dst_creds = home / "credentials"
            dst_creds.mkdir(exist_ok=True)
            for c in src_creds.glob("*.json"):
                d = dst_creds / c.name
                if not d.exists() or c.stat().st_mtime > d.stat().st_mtime:
                    with contextlib.suppress(Exception):
                        shutil.copy2(c, d)
        return home

    def _empty_skills_dir(self) -> Path:
        return self._isolated_kimi_home() / "no-skills"

    def _copy_session_jsonl(self, workdir: Path, transcript: str, dest: Path) -> None:
        """Copy kimi's ``wire.jsonl`` (the complete agent record, every tool call).

        Sessions live under ``<KIMI_CODE_HOME>/sessions/<workDirKey>/<sessionId>/
        agents/main/wire.jsonl``; each backend call runs in a fresh temp workdir,
        so the most recently written wire log is this call's.
        """
        try:
            root = self._isolated_kimi_home() / "sessions"
            wires = sorted(
                root.glob("*/*/agents/main/wire.jsonl"),
                key=lambda p: p.stat().st_mtime,
            )
            if wires:
                shutil.copy2(wires[-1], dest)
        except Exception:  # noqa: BLE001
            pass
