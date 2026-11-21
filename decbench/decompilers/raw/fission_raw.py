"""Raw Fission decompiler backend (native or Dockerized, via ``fission_cli``).

Fission (https://github.com/fission-systems/Fission) lifts machine code via a
pure-Rust SLEIGH runtime into SSA p-code and NIR/HIR structured C pseudocode.
It ships as a standalone CLI (``fission_cli``), so this backend shells out to it
with JSON output rather than importing a native Python module.

Two invocation shapes, both load-once/decompile-many in a single process:

* target-scoped (the benchmark case) — decompile a single requested address with
  ``--addr 0x...`` or multiple DWARF targets with ``--addresses-file <path>``::

      fission_cli --no-db decomp <binary> --json --no-header --no-warnings \\
          --addresses-file <path> --timeout-ms <ms>

* whole-binary fallback (bare ``decbench run`` with no target set)::

      fission_cli --no-db decomp <binary> --json --no-header --no-warnings \\
          --all --limit <N> --timeout-ms <ms>

Both emit ``[{"address": "0x...", "name": "...", "size": <int>, "code": "<C>",
"fell_back": <bool>, "variables": [...], "line_mappings": [...]}, ...]``.

Fission reports addresses in the binary's own link/file space (same as
ida/binja/kuna/glaurung on non-PIE ELFs) and preserves both structured
``variables`` (with ABI ``arg_index``, frame ``stack_offset``, and defining/use
instruction ``addresses``) and per-line ``line_mappings`` in the JSON payload.
Call-site-only rows (``call_site`` with empty ``defined_variables``) are carried
in ``metadata["call_mappings"]`` so they are not conflated with variable
line-address evidence, while assignment definition rows populate
``FunctionDecompilation.line_mappings`` so Fission reaches the
address-correspondence path in ``type_match`` cleanly.

Locate the CLI via ``$FISSION_BIN`` (an explicit path), the DecBench
decompiler configuration, or ``fission_cli`` / ``fission`` on ``$PATH``. When
no native CLI resolves, the backend uses the image built by
``decbench decompiler-build fission``.
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
import tempfile
import time
from collections import Counter
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

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOCKER_DIR = _REPO_ROOT / "docker"
_IMAGE_REV_FILE = "/opt/fission.rev"
_DEFAULT_REPO = "https://github.com/fission-systems/Fission.git"
_DEFAULT_REF = "5073a1c63dcf15b57f4506671aa16ac1cc0c47b7"
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _executable(path: Path) -> Path | None:
    """Return ``path`` only when it names an executable file."""
    return path if path.is_file() and os.access(path, os.X_OK) else None


def _fission_bin(version: str | None = None) -> Path | None:
    """Resolve native ``fission_cli`` with explicit configuration taking precedence."""
    configured = os.environ.get("FISSION_BIN")
    if configured:
        return _executable(Path(configured))

    settings = [version_settings("fission", version)]
    default = load_versions_config().get("fission")
    if isinstance(default, dict):
        settings.append(default)
    for source in settings:
        binary = source.get("binary") or source.get("bin")
        if binary:
            executable = _executable(Path(str(binary)).expanduser())
            if executable is not None:
                return executable

    discovered = shutil.which("fission_cli") or shutil.which("fission")
    return Path(discovered) if discovered else None


def _looks_like_resource_root(path: Path) -> bool:
    """Whether ``path`` looks like a Fission resource bundle root."""
    return (path / "sleigh-specs").is_dir()


def _resolve_resource_root(executable: Path | None, version: str | None = None) -> Path | None:
    """Resolve optional ``--resource-root`` directory for native ``fission_cli``."""
    env_root = os.environ.get("FISSION_RESOURCE_ROOT")
    if env_root:
        candidate = Path(env_root).expanduser()
        if candidate.is_dir():
            return candidate

    settings = [version_settings("fission", version)]
    default = load_versions_config().get("fission")
    if isinstance(default, dict):
        settings.append(default)
    for source in settings:
        configured_root = source.get("resource_root")
        if configured_root:
            candidate = Path(str(configured_root)).expanduser()
            if candidate.is_dir():
                return candidate

    if executable is not None:
        resolved = executable.resolve()
        for candidate in (
            resolved.parent.parent / "share" / "fission",
            resolved.parent.parent.parent / "utils",
            resolved.parent.parent / "utils",
        ):
            if _looks_like_resource_root(candidate):
                return candidate
    return None


def _git(cwd: Path, *args: str) -> str | None:
    """Run ``git -C cwd args`` and return its stripped stdout, or ``None``."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        process = subprocess.run(
            [git, "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:  # noqa: BLE001
        return None
    if process.returncode != 0:
        return None
    return process.stdout.strip()


def _checkout_revision(executable: Path) -> tuple[str, bool] | None:
    """The git checkout ``executable`` sits in, and whether it provably built it.

    A ``target/release/fission_cli`` inside a Fission checkout is usually the
    checkout's own build, but not always: the tree may have been switched to
    another branch, pulled or edited after the build, and a result recorded
    under the new ``HEAD`` would name code that never ran. The revision is
    claimed only when the tree has no uncommitted changes to tracked files and
    the binary is newer than both the ``HEAD`` commit and the last time
    ``HEAD`` moved (a checkout or switch rewrites ``.git/HEAD``).

    Returns ``(short_sha, matches)``, or ``None`` outside a git checkout.
    """
    where = executable.resolve().parent
    revision = _git(where, "rev-parse", "--short", "HEAD")
    if not revision:
        return None
    dirty = _git(where, "status", "--porcelain", "--untracked-files=no")
    commit_time = _git(where, "log", "-1", "--format=%ct", "HEAD")
    head_file = _git(where, "rev-parse", "--git-path", "HEAD")
    if dirty is None or commit_time is None or head_file is None:
        return revision, False
    head_path = Path(head_file)
    if not head_path.is_absolute():
        head_path = where / head_path
    try:
        built = executable.resolve().stat().st_mtime
        moved = head_path.stat().st_mtime
    except OSError:
        return revision, False
    matches = not dirty and built >= max(float(commit_time), moved)
    return revision, matches


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
        _l.warning("fission: git is unavailable; cannot resolve %s", ref)
        return None
    try:
        process = subprocess.run(
            [git, "ls-remote", repo, ref],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as error:  # noqa: BLE001
        _l.warning("fission: could not resolve %s in %s: %s", ref, repo, error)
        return None
    if process.returncode != 0 or not process.stdout.strip():
        _l.warning("fission: %s does not name a ref in %s", ref, repo)
        return None
    return process.stdout.split()[0]


@register_decompiler("fission")
class RawFissionDecompiler(Decompiler):
    """Fission (native Rust SLEIGH/NIR decompiler) driven via ``fission_cli``."""

    name = "fission"
    display_name = "Fission"
    image = "decbench/fission:latest"
    dockerfile = "fission.Dockerfile"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._payload_cache: dict[tuple[str, frozenset[int] | None], list[dict[str, Any]]] = {}
        self._version_probed = False
        self._version_value: str | None = None

    @property
    def _image(self) -> str:
        return os.environ.get("FISSION_IMAGE") or self.image

    def _fission_bin(self) -> Path | None:
        return _fission_bin(self.requested_version)

    def _select_path(self) -> tuple[str, Path | None]:
        executable = self._fission_bin()
        if executable is not None:
            return "native", executable
        if _image_present(self._image):
            return "docker", None
        return "none", None

    def is_available(self) -> bool:
        return self._select_path()[0] != "none"

    @classmethod
    def build_image(cls, no_cache: bool = False) -> int:
        """Build the pinned Fission image used when no native CLI resolves."""
        docker = _docker_bin()
        if docker is None:
            raise RuntimeError("docker binary not found on PATH")
        dockerfile = _DOCKER_DIR / cls.dockerfile
        if not dockerfile.is_file():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile}")

        image = os.environ.get("FISSION_IMAGE") or cls.image
        repo = os.environ.get("FISSION_REPO") or _DEFAULT_REPO
        ref = os.environ.get("FISSION_REF") or _DEFAULT_REF
        resolved = _resolve_ref(repo, ref)
        if resolved is None:
            no_cache = True
            _l.warning(
                "fission: building without cache because %s could not be resolved",
                ref,
            )

        command = [docker, "build", "-f", str(dockerfile), "-t", image]
        command += ["--build-arg", f"FISSION_REPO={repo}"]
        command += ["--build-arg", f"FISSION_REF={resolved or ref}"]
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
        configured = os.environ.get("FISSION_VERSION")
        if configured:
            return configured
        mode, executable = self._select_path()
        if mode == "docker":
            return self._docker_version()
        if executable is None:
            return None

        version = ""
        built_from: str | None = None
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
            # A build that names its own commit (`fission_cli 0.3.0 (abc1234)`)
            # is the only source that cannot drift from the binary.
            built = re.search(r"\(([0-9a-fA-F]{7,40})\)", out)
            if built:
                built_from = built.group(1)
        except Exception:  # noqa: BLE001
            pass
        if built_from:
            suffix = f" (fission {version})" if version else ""
            return f"git-{built_from}{suffix}"

        checkout = _checkout_revision(executable)
        if checkout is None:
            return version or self.requested_version or "unknown"
        revision, matches = checkout
        suffix = f" (fission {version})" if version else ""
        if matches:
            return f"git-{revision}{suffix}"
        # The checkout around the binary is not proven to be what built it:
        # say which checkout it sits in without claiming it as the revision.
        return f"{version or 'unknown'} (unverified build in checkout git-{revision})"

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
                _l.debug("fission: could not read image revision: %s", error)
        return self._image.rsplit(":", 1)[-1] if ":" in self._image else "unknown"

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Enumerate (name, ELF-file-space addr) for the benchmarkable functions."""
        if not self.is_available():
            return []
        try:
            records = self._run_decompile(binary_path, function_names=None)
        except Exception as e:  # noqa: BLE001
            _l.error("fission-raw: discover failed on %s: %s", binary_path, e)
            return []
        text_range = common.elf_text_range(binary_path)
        out: list[tuple[str, int]] = []
        for record in records:
            addr = self._record_address(record)
            if addr is None:
                continue
            name = str(record.get("name") or f"sub_{addr:x}")
            if not common.should_skip_function(name, addr, text_range):
                out.append((name, addr))
        return sorted(out, key=lambda x: x[1])

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary in one CLI invocation (load-once)."""
        run_via, _ = self._select_path()
        if run_via == "none":
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available "
                "(set FISSION_BIN, install fission_cli on PATH, or run "
                f"`decbench decompiler-build {self.name}`)"
            )

        start = time.time()
        text_range = common.elf_text_range(binary_path)
        addr_targets = common.addr_targets_of(function_names)
        explicit_addrs = {int(a): n for n, a in functions} if functions else {}
        requested_addrs = addr_targets or set(explicit_addrs)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        timed_out = False

        def _meta(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {
                "backend": "fission",
                "via": "raw",
                "run_via": run_via,
                "slice_scoped": bool(requested_addrs or functions),
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

        if functions is not None and not functions:
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

        try:
            records = self._run_decompile(
                binary_path,
                function_names=requested_addrs or None,
            )
        except subprocess.TimeoutExpired as e:
            timed_out = True
            _l.warning("fission-raw timed out on %s: %s", binary_path, e)
            return self._error_result(
                binary_path,
                start,
                "timeout",
                run_via,
                timed_out=True,
                slice_scoped=bool(requested_addrs or functions),
            )
        except Exception as e:  # noqa: BLE001
            _l.error("fission-raw failed on %s: %s", binary_path, e)
            return self._error_result(
                binary_path,
                start,
                str(e),
                run_via,
                slice_scoped=bool(requested_addrs or functions),
            )

        by_addr: dict[int, dict[str, Any]] = {}
        for rec in records:
            addr = self._record_address(rec)
            if addr is None:
                continue
            by_addr[addr] = rec

        enumerated: list[tuple[str, int]] = []
        for addr in sorted(by_addr):
            rec = by_addr[addr]
            name = explicit_addrs.get(addr) or str(rec.get("name") or f"sub_{addr:x}")
            if common.should_skip_function(name, addr, text_range, addr_targets or None):
                continue
            enumerated.append((name, addr))

        if functions is not None:
            wanted_addrs = {int(a) for _n, a in functions}
            enumerated = [(n, a) for (n, a) in enumerated if common._addr_matches(a, wanted_addrs)]

        if not addr_targets and isinstance(function_names, set):
            str_names = {x for x in function_names if isinstance(x, str)}
            if str_names:
                enumerated = [(n, a) for (n, a) in enumerated if n in str_names]

        enumerated = common.narrow_to_source(
            enumerated, addr_targets, backend="fission", binary_name=binary_path.name
        )

        for func_name, file_addr in enumerated:
            fd = None
            try:
                fd = self._build_function(by_addr[file_addr], func_name, file_addr)
            except Exception as e:  # noqa: BLE001
                _l.debug("fission-raw: assembling %s failed: %s", func_name, e)
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

    def _build_command(
        self,
        binary_path: Path,
        function_names: set[int] | None,
        addresses_file: Path | None = None,
    ) -> list[str]:
        mode, executable = self._select_path()
        if mode == "none":
            raise RuntimeError("no native Fission executable or local Docker image")
        run_path = str(binary_path)
        container_addrs_path = "/in/addresses.txt"
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
            ]
            if addresses_file is not None:
                cmd += ["-v", f"{addresses_file.resolve()}:{container_addrs_path}:ro"]
            cmd.append(self._image)
        else:
            assert executable is not None
            cmd = [str(executable)]
            resource_root = _resolve_resource_root(executable, self.requested_version)
            if resource_root is not None:
                cmd += ["--resource-root", str(resource_root)]

        cmd += [
            "--no-db",
            "decomp",
            run_path,
            "--json",
            "--no-header",
            "--no-warnings",
        ]
        if addresses_file is not None:
            cmd += [
                "--addresses-file",
                container_addrs_path if mode == "docker" else str(addresses_file),
            ]
        elif function_names and len(function_names) == 1:
            only_addr = int(next(iter(function_names)))
            cmd += ["--addr", hex(only_addr)]
        else:
            limit = os.environ.get("DECBENCH_FISSION_LIMIT", "30000")
            cmd += ["--all", "--limit", str(int(limit))]

        fn_ms = os.environ.get("DECBENCH_FISSION_TIMEOUT_MS")
        if fn_ms in (None, ""):
            fn_ms = str(int(self.config.function_timeout_seconds * 1000))
        cmd += ["--timeout-ms", str(int(fn_ms))]
        return cmd

    @staticmethod
    def _kill_group(p: subprocess.Popen) -> None:
        """SIGKILL fission_cli's whole process group (pgid == pid via start_new_session)."""
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(Exception):
                p.kill()
        with contextlib.suppress(Exception):
            p.wait(timeout=15)

    def _timeout_seconds(self) -> float | None:
        env = os.environ.get("DECBENCH_FISSION_TIMEOUT")
        if env:
            try:
                return int(env)
            except ValueError:
                _l.warning("ignoring non-integer DECBENCH_FISSION_TIMEOUT=%r", env)
        return self.config.binary_timeout_seconds

    def _run_decompile(
        self, binary_path: Path, function_names: set[int] | None
    ) -> list[dict[str, Any]]:
        """Run ``fission_cli decomp ... --json`` and parse the JSON records.

        Cached per (resolved path, target-set) so ``discover_functions`` +
        ``decompile_binary`` don't pay for two loads.
        """
        key = (
            str(binary_path),
            None if function_names is None else frozenset(function_names),
        )
        if key in self._payload_cache:
            return self._payload_cache[key]

        with tempfile.TemporaryDirectory(prefix="decbench-fission-") as tmpdir:
            addresses_file: Path | None = None
            if function_names and len(function_names) > 1:
                addresses_file = Path(tmpdir) / "addresses.txt"
                addresses_file.write_text(
                    "".join(f"0x{int(a):x}\n" for a in sorted(function_names))
                )
            cmd = self._build_command(binary_path, function_names, addresses_file=addresses_file)
            _l.debug("fission run: %s", " ".join(cmd))
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.environ.get("FISSION_WORKING_DIR"),
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
            raise RuntimeError(f"fission exited {p.returncode}: {tail}")
        records = self._parse_records(stdout)
        self._payload_cache[key] = records
        return records

    @staticmethod
    def _parse_records(stdout: str) -> list[dict[str, Any]]:
        """Parse Fission's JSON output, supporting list or benchmark envelope forms."""
        text = (stdout or "").strip()
        if not text:
            return []
        payload = json.loads(text)
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        if isinstance(payload, dict):
            functions = payload.get("functions")
            if isinstance(functions, list):
                return [r for r in functions if isinstance(r, dict)]
            return [payload]
        return []

    @classmethod
    def _record_address(cls, rec: dict[str, Any]) -> int | None:
        raw = rec.get("address", rec.get("entry_va"))
        if raw is None:
            return None
        addr = cls._as_int(raw, -1)
        return addr if addr >= 0 else None

    def _build_function(
        self, rec: dict[str, Any], name: str, file_addr: int
    ) -> FunctionDecompilation | None:
        if rec.get("fell_back") or rec.get("error") or rec.get("fallback") == "assembly":
            return None
        code = rec.get("code") or rec.get("code_nir") or rec.get("pseudocode")
        if not code or not str(code).strip():
            return None
        code = str(code)
        line_count = len(code.splitlines()) or 1
        record_addr = self._as_int(rec.get("address", rec.get("entry_va")), file_addr)
        size = self._as_int(rec.get("size"), 0)
        address_delta = file_addr - record_addr

        def _evidence_address(value: Any) -> int | None:
            address = self._as_int(value, -1)
            if address < record_addr:
                return None
            if size > 0 and address >= record_addr + size:
                return None
            return address + address_delta

        raw_mappings = rec.get("line_mappings")
        if raw_mappings is None:
            raw_mappings = rec.get("line_mappings_nir")

        line_to_addresses: dict[int, set[int]] = {}
        call_mappings: list[dict[str, Any]] = []
        defined_lines_by_var: dict[str, set[int]] = {}

        for mapping in raw_mappings or []:
            if not isinstance(mapping, dict):
                continue
            line_number = self._as_int(mapping.get("line_number"), 0)
            if not 1 <= line_number <= line_count:
                continue
            addresses = {
                rebased
                for value in mapping.get("addresses") or []
                if (rebased := _evidence_address(value)) is not None
            }
            if not addresses:
                continue

            call_site = mapping.get("call_site")
            defined_vars = mapping.get("defined_variables")
            # Call-site-only rows carry call provenance rather than variable
            # assignments; keep them separated so legacy line checks do not
            # misattribute RHS variables at calls.
            if call_site is not None and not defined_vars:
                rebased_call_site = dict(call_site) if isinstance(call_site, dict) else call_site
                if (
                    isinstance(rebased_call_site, dict)
                    and "instruction_address" in rebased_call_site
                ):
                    rebased_cs_addr = _evidence_address(rebased_call_site["instruction_address"])
                    if rebased_cs_addr is not None:
                        rebased_call_site["instruction_address"] = rebased_cs_addr
                call_mappings.append(
                    {
                        "line_number": line_number,
                        "addresses": sorted(addresses),
                        "defined_variables": [],
                        "call_site": rebased_call_site,
                    }
                )
                continue

            line_to_addresses.setdefault(line_number, set()).update(addresses)
            if isinstance(defined_vars, list):
                for var_name in defined_vars:
                    if var_name:
                        defined_lines_by_var.setdefault(str(var_name), set()).add(line_number)

        variables = self._variables(rec, line_count, _evidence_address, defined_lines_by_var)
        extra_meta: dict[str, Any] = dict(common.extract_metrics(code))
        if call_mappings:
            extra_meta["call_mappings"] = call_mappings

        return FunctionDecompilation(
            name=name,
            address=file_addr,
            decompiled_code=code,
            line_count=line_count,
            line_mappings=common.merge_line_addresses(line_to_addresses),
            variables=variables,
            metadata=extra_meta,
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
        defined_lines_by_var: dict[str, set[int]],
    ) -> list[VariableInfo]:
        """Extract Fission's structured variable inventory within the function span."""
        raw_vars = [v for v in (rec.get("variables") or []) if isinstance(v, dict)]
        name_counts = Counter(str(v.get("name") or "") for v in raw_vars)
        out: list[VariableInfo] = []
        for v in raw_vars:
            name = str(v.get("name") or "")
            if not name:
                continue
            raw_kind = str(v.get("kind") or "stack")
            kind = raw_kind if raw_kind in {"arg", "stack", "reg"} else "stack"
            if v.get("line_numbers") is not None:
                line_numbers = sorted(
                    {
                        line_number
                        for value in v.get("line_numbers") or []
                        if 0 < (line_number := RawFissionDecompiler._as_int(value, 0)) <= line_count
                    }
                )
            elif name_counts[name] == 1:
                line_numbers = sorted(defined_lines_by_var.get(name, set()))
            else:
                line_numbers = []
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
                    kind=kind,
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
            "backend": "fission",
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
