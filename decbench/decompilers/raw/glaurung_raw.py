"""Raw Glaurung decompiler backend (native, via the glaurung CLI).

Glaurung (https://github.com/mjbommar/glaurung) is a reverse-engineering
framework whose deterministic decompiler is a Rust LLIR pipeline (CFG discovery
→ lift → SSA → control-flow structuring → AST lowering → expression
reconstruction → DCE → name/arg/type recovery). Like ``kuna``, it ships as a
standalone CLI, so this backend *shells out* to it and parses JSON rather than
importing a native Python module.

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
firmware is Cortex-M Thumb, so this covers the ARM slice). ARM32 mode selection
uses ELF mapping symbols, function-symbol Thumb bits, and bounded decode probes;
both Thumb-2 and A32 have dedicated round-trip lanes.

The CLI reports a structured ``variables`` inventory and per-line
``line_mappings`` in the same JSON payload, and both are forwarded here: the
inventory carries frame offsets and the machine addresses that touch each slot,
which a parse of the emitted C cannot recover, and the line map is what lets a
producer outside ``ADDRESS_CORRESPONDENCE_BACKENDS`` reach the
address-correspondence path in type_match at all.

Locate the CLI via ``$GLAURUNG_BIN`` (an explicit path), the DecBench
decompiler configuration, or ``glaurung`` on ``$PATH``. When no native CLI
resolves, the backend uses the image built by
``decbench decompiler-build glaurung``.
"""

from __future__ import annotations

import contextlib
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
from decbench.decompilers.limits import (
    cleanup_docker_invocation,
    docker_memory_args,
    docker_tracking_args,
)
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.decompilers.spec import load_versions_config, version_settings
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    VariableInfo,
)

_l = logging.getLogger(__name__)

# Above this many targets we skip the (command-line-length-bounded) --vas form
# and decompile the whole binary, then narrow. The sample-set takes at most one
# function per binary, so --vas is the normal path; this is just a safety valve.
_MAX_VAS_INLINE = 400

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOCKER_DIR = _REPO_ROOT / "docker"
_IMAGE_REV_FILE = "/opt/glaurung.rev"
_DEFAULT_REPO = "https://github.com/mjbommar/glaurung.git"
_DEFAULT_REF = "fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4"
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _executable(path: Path) -> Path | None:
    """Return ``path`` only when it names an executable file."""
    return path if path.is_file() and os.access(path, os.X_OK) else None


def _glaurung_bin(version: str | None = None) -> Path | None:
    """Resolve native Glaurung with explicit configuration taking precedence."""
    configured = os.environ.get("GLAURUNG_BIN")
    if configured:
        return _executable(Path(configured))

    settings = [version_settings("glaurung", version)]
    default = load_versions_config().get("glaurung")
    if isinstance(default, dict):
        settings.append(default)
    for source in settings:
        binary = source.get("binary")
        if binary:
            executable = _executable(Path(str(binary)).expanduser())
            if executable is not None:
                return executable

    discovered = shutil.which("glaurung")
    return Path(discovered) if discovered else None


def _docker_bin() -> str | None:
    return shutil.which("docker")


def _image_present(image: str) -> bool:
    """Whether ``image`` exists locally, without building or pulling it."""
    docker = _docker_bin()
    if not docker or not image:
        return False
    try:
        process = subprocess.run(
            [docker, "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except Exception:  # noqa: BLE001
        return False
    return process.returncode == 0


def _resolve_ref(repo: str, ref: str) -> str | None:
    """Resolve a source ref to an immutable SHA for an honest Docker rebuild."""
    if _SHA.fullmatch(ref):
        return ref
    git = shutil.which("git")
    if git is None:
        _l.warning("glaurung: git is unavailable; cannot resolve %s", ref)
        return None
    try:
        process = subprocess.run(
            [git, "ls-remote", repo, ref],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as error:  # noqa: BLE001
        _l.warning("glaurung: could not resolve %s in %s: %s", ref, repo, error)
        return None
    if process.returncode != 0 or not process.stdout.strip():
        _l.warning("glaurung: %s does not name a ref in %s", ref, repo)
        return None
    return process.stdout.split()[0]


@register_decompiler("glaurung")
class RawGlaurungDecompiler(Decompiler):
    """Glaurung (native Rust LLIR decompiler) driven via its CLI."""

    name = "glaurung"
    display_name = "Glaurung"
    image = "decbench/glaurung:latest"
    dockerfile = "glaurung.Dockerfile"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._payload_cache: dict[tuple[str, frozenset[int] | None], list[dict[str, Any]]] = {}
        self._version_probed = False
        self._version_value: str | None = None

    #
    # Locating the binary (mirrors kuna_raw's $KUNA_BIN / which)
    #

    @property
    def _image(self) -> str:
        return os.environ.get("GLAURUNG_IMAGE") or self.image

    def _glaurung_bin(self) -> Path | None:
        return _glaurung_bin(self.requested_version)

    def _select_path(self) -> tuple[str, Path | None]:
        executable = self._glaurung_bin()
        if executable is not None:
            return "native", executable
        if _image_present(self._image):
            return "docker", None
        return "none", None

    #
    # Decompiler interface
    #

    def is_available(self) -> bool:
        return self._select_path()[0] != "none"

    @classmethod
    def build_image(cls, no_cache: bool = False) -> int:
        """Build the pinned Glaurung image used when no native CLI resolves."""
        docker = _docker_bin()
        if docker is None:
            raise RuntimeError("docker binary not found on PATH")
        dockerfile = _DOCKER_DIR / cls.dockerfile
        if not dockerfile.is_file():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile}")

        image = os.environ.get("GLAURUNG_IMAGE") or cls.image
        repo = os.environ.get("GLAURUNG_REPO") or _DEFAULT_REPO
        ref = os.environ.get("GLAURUNG_REF") or _DEFAULT_REF
        resolved = _resolve_ref(repo, ref)
        if resolved is None:
            no_cache = True
            _l.warning(
                "glaurung: building without cache because %s could not be resolved",
                ref,
            )

        command = [docker, "build", "-f", str(dockerfile), "-t", image]
        command += ["--build-arg", f"GLAURUNG_REPO={repo}"]
        command += ["--build-arg", f"GLAURUNG_REF={resolved or ref}"]
        if no_cache:
            command.append("--no-cache")
        command.append(str(_DOCKER_DIR))
        return subprocess.run(command).returncode

    def get_version(self) -> str | None:
        if not self._version_probed:
            self._version_value = self._probe_version()
            self._version_probed = True
        return self._version_value

    def _probe_version(self) -> str | None:
        configured = os.environ.get("GLAURUNG_VERSION")
        if configured:
            return configured
        mode, executable = self._select_path()
        if mode == "docker":
            return self._docker_version()
        if executable is None:
            return None

        version = ""
        try:
            p = subprocess.run(
                [str(executable), "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            out = (p.stdout or p.stderr or "").strip()
            m = re.search(r"(\d+\.\d+\.\d+\S*)", out)
            if m:
                version = m.group(1)
            elif out:
                version = out.splitlines()[0]
        except Exception:  # noqa: BLE001
            pass

        try:
            revision = subprocess.run(
                ["git", "-C", str(executable.resolve().parent), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if revision.returncode == 0 and revision.stdout.strip():
                suffix = f" (glaurung {version})" if version else ""
                return f"git-{revision.stdout.strip()}{suffix}"
        except Exception:  # noqa: BLE001
            pass
        return version or self.requested_version or "unknown"

    def _docker_version(self) -> str:
        docker = _docker_bin()
        if docker:
            try:
                process = subprocess.run(
                    [
                        docker,
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--entrypoint",
                        "cat",
                        self._image,
                        _IMAGE_REV_FILE,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if process.returncode == 0 and process.stdout.strip():
                    return f"git-{process.stdout.strip()}"
            except Exception as error:  # noqa: BLE001
                _l.debug("glaurung: could not read image revision: %s", error)
        return self._image.rsplit(":", 1)[-1] if ":" in self._image else "unknown"

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
        out = [(str(r.get("name") or ""), int(r.get("entry_va") or 0)) for r in records]
        out = [(n, a) for (n, a) in out if not common.should_skip_function(n, a, text_range)]
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
        run_via, _ = self._select_path()
        if run_via == "none":
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available "
                "(set GLAURUNG_BIN, install glaurung on PATH, or run "
                f"`decbench decompiler-build {self.name}`)"
            )

        start = time.time()
        text_range = common.elf_text_range(binary_path)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        timed_out = False

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {
                "backend": "glaurung",
                "via": "raw",
                "run_via": run_via,
                "slice_scoped": bool(function_names or functions),
            }
            if run_via == "docker":
                extra["image"] = self._image
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
            return self._error_result(
                binary_path,
                start,
                "timeout",
                run_via,
                timed_out=True,
                slice_scoped=bool(function_names or functions),
            )
        except Exception as e:  # noqa: BLE001
            _l.error("glaurung-raw failed on %s: %s", binary_path, e)
            return self._error_result(
                binary_path, start, str(e), run_via, slice_scoped=bool(function_names or functions)
            )

        # 2. Index by name, filter to the benchmarkable + source-narrowed set.
        by_name = {str(r.get("name") or ""): r for r in records}
        enumerated = sorted(
            (
                (n, int(r.get("entry_va") or 0))
                for n, r in by_name.items()
                if not common.should_skip_function(n, int(r.get("entry_va") or 0), text_range)
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

    def _build_command(self, binary_path: Path, function_names: set[int] | None) -> list[str]:
        mode, executable = self._select_path()
        if mode == "none":
            raise RuntimeError("no native Glaurung executable or local Docker image")
        run_path = str(binary_path)
        if mode == "docker":
            docker = _docker_bin()
            if docker is None:
                raise RuntimeError("docker binary not found on PATH")
            run_path = f"/in/{binary_path.name}"
            cmd = [
                docker,
                "run",
                "--rm",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                *docker_tracking_args(),
                *docker_memory_args(),
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "-e",
                "HOME=/tmp",
                "-v",
                f"{binary_path.resolve()}:{run_path}:ro",
                self._image,
            ]
        else:
            assert executable is not None
            cmd = [str(executable)]
        cmd += ["decompile", run_path, "--style", "decbench", "--format", "json"]
        # Target-scoped when we know the DWARF target set and it is small enough
        # for the command line; otherwise decompile the whole binary and narrow.
        if function_names and len(function_names) <= _MAX_VAS_INLINE:
            cmd += ["--vas", ",".join(hex(int(a)) for a in sorted(function_names))]
        else:
            limit = os.environ.get("DECBENCH_GLAURUNG_LIMIT", "30000")
            cmd += ["--all", "--limit", str(int(limit))]
        # Glaurung accepts milliseconds while DecBench's shared policy uses seconds.
        fn_ms = os.environ.get("DECBENCH_GLAURUNG_TIMEOUT_MS")
        if fn_ms in (None, ""):
            fn_ms = str(int(self.config.function_timeout_seconds * 1000))
        cmd += ["--timeout-ms", str(int(fn_ms))]
        return cmd

    @staticmethod
    def _kill_group(p: subprocess.Popen) -> None:
        """SIGKILL glaurung's whole process group (pgid == pid via start_new_session)."""
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(Exception):
                p.kill()
        with contextlib.suppress(Exception):
            p.wait(timeout=15)

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
        key = (
            str(binary_path),
            None if function_names is None else frozenset(function_names),
        )
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
                cleanup_docker_invocation(cmd)
        if p.returncode != 0:
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
        line_count = code.count("\n") + 1
        record_addr = self._as_int(rec.get("entry_va"), file_addr)
        size = self._as_int(rec.get("size"), 0)
        address_delta = file_addr - record_addr

        def _evidence_address(value: Any) -> int | None:
            address = self._as_int(value, -1)
            if address < record_addr:
                return None
            if size > 0 and address >= record_addr + size:
                return None
            return address + address_delta

        line_to_addresses: dict[int, set[int]] = {}
        for mapping in rec.get("line_mappings") or []:
            line_number = self._as_int(mapping.get("line_number"), 0)
            if not 1 <= line_number <= line_count:
                continue
            addresses = {
                rebased
                for value in mapping.get("addresses") or []
                if (rebased := _evidence_address(value)) is not None
            }
            if addresses:
                line_to_addresses.setdefault(line_number, set()).update(addresses)
        return FunctionDecompilation(
            name=name,
            address=file_addr,
            decompiled_code=code,
            line_count=line_count,
            line_mappings=common.merge_line_addresses(line_to_addresses),
            variables=self._variables(rec, line_count, _evidence_address),
            metadata=common.extract_metrics(code),
        )

    @staticmethod
    def _as_int(value: Any, default: int) -> int:
        try:
            return int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _variables(
        rec: dict[str, Any],
        line_count: int,
        address_converter: Any,
    ) -> list[VariableInfo]:
        """Glaurung's structured inventory, filtered to this function's span.

        Glaurung reports `size: null` for many functions; the converter then
        skips the upper bound rather than rejecting every address, because a
        zero-length span would silently discard the whole payload.
        """
        out: list[VariableInfo] = []
        for v in rec.get("variables") or []:
            name = str(v.get("name") or "")
            if not name:
                continue
            kind = str(v.get("kind") or "stack")
            line_numbers = sorted(
                {
                    line_number
                    for value in v.get("line_numbers") or []
                    if 0 < (line_number := RawGlaurungDecompiler._as_int(value, 0)) <= line_count
                }
            )
            addresses = sorted(
                {
                    converted
                    for value in v.get("addresses") or []
                    if (converted := address_converter(value)) is not None and converted >= 0
                }
            )
            out.append(
                VariableInfo(
                    name=name,
                    type=str(v.get("type") or ""),
                    stack_offset=(
                        int(v["stack_offset"]) if v.get("stack_offset") is not None else None
                    ),
                    size=(int(v["size"]) if v.get("size") is not None else None),
                    kind="arg" if kind == "arg" else "stack",
                    arg_index=(int(v["arg_index"]) if v.get("arg_index") is not None else None),
                    line_numbers=line_numbers,
                    addresses=addresses,
                )
            )
        return out

    def _error_result(
        self,
        binary_path: Path,
        start: float,
        err: str,
        run_via: str,
        timed_out: bool = False,
        slice_scoped: bool = False,
    ) -> DecompilationResult:
        extra: dict[str, Any] = {
            "error": err,
            "backend": "glaurung",
            "via": "raw",
            "run_via": run_via,
            "slice_scoped": slice_scoped,
        }
        if run_via == "docker":
            extra["image"] = self._image
        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                timeout_occurred=timed_out,
                failed_functions=["all"],
                extra=extra,
            ),
        )
