"""Container-backed and external-tool decompiler plugins.

This module hosts decompilers that decbench does **not** drive through declib,
because they ship as standalone CLIs rather than Python libraries:

- **Reko** (``reko``) — .NET decompiler, run inside a Docker image.
- **RetDec** (``retdec``) — LLVM-based decompiler, run inside a Docker image.
- **r2dec** (``r2dec``) — radare2's pseudo-decompiler. radare2 is installed on
  this machine, so r2dec prefers a **native** run via ``r2pipe`` and only falls
  back to a Docker image when neither the native r2dec plugin nor the built-in
  ``pdc`` pseudo-decompiler is usable.

Common design (:class:`DockerizedDecompiler`):
    The container is run with the target binary bind-mounted **read-only**; the
    decompiler emits whole-program C, which we then split into per-function
    snippets. Function *names and addresses* come from the binary's ELF symbol
    table (via pyelftools), so addresses live in **ELF file space** and line up
    with DWARF and the rest of decbench — the same convention declib_dec uses.

    These tools do not expose stack variables / line mappings uniformly, so
    ``FunctionDecompilation.variables`` and ``.line_mappings`` are left empty.
    The metrics degrade gracefully: GED still parses the recovered C, byte_match
    recompiles it, and type_match falls back to regex/name parsing.

Images are **not** auto-built. ``is_available()`` only reports whether the image
already exists locally; build it explicitly with ``decbench decompiler-build
<name>`` (which calls :meth:`DockerizedDecompiler.build_image`).
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

_l = logging.getLogger(__name__)

# Repo root: decbench/decompilers/dockerized.py -> repo root is parents[2].
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_DIR = _REPO_ROOT / "docker"

# CRT/compiler-generated functions that are not user code (mirrors declib_dec).
_SKIP_NAMES = frozenset({
    "_start", "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
    "_init", "_fini", "__do_global_dtors_aux", "register_tm_clones",
    "deregister_tm_clones", "frame_dummy", "__libc_start_call_main",
    "_dl_relocate_static_pie", "__gmon_start__", "__stack_chk_fail",
})

# Name prefixes for thunks/imports that should not be benchmarked.
_SKIP_PREFIXES = ("thunk_", "j_", "__imp_", ".plt", "_dl_")


# --------------------------------------------------------------------------- #
# ELF helpers (symbol table -> ELF-file-space function addresses)
# --------------------------------------------------------------------------- #

def _elf_text_range(binary_path: Path) -> tuple[int, int] | None:
    """[start, end) virtual-address range of the ``.text`` section, or None."""
    try:
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            if text is None:
                return None
            start = text["sh_addr"]
            return (start, start + text["sh_size"])
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to read .text range for %s: %s", binary_path, e)
        return None


def elf_function_symbols(binary_path: Path) -> list[tuple[str, int]]:
    """Enumerate ``(name, address)`` for benchmarkable functions via ELF symbols.

    Addresses are in **ELF file space** (``st_value``), which matches DWARF and
    the declib-backed decompilers. CRT/compiler helpers, import thunks, and
    anything outside ``.text`` are filtered out. Returned sorted by address.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except Exception as e:  # noqa: BLE001
        _l.debug("pyelftools unavailable: %s", e)
        return []

    text_range = _elf_text_range(binary_path)
    out: dict[str, int] = {}
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            # Prefer the full .symtab; .dynsym rarely has STT_FUNC for static fns.
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    addr = int(sym["st_value"])
                    name = sym.name or ""
                    if not addr or not name:
                        continue
                    if name in _SKIP_NAMES:
                        continue
                    if text_range is not None:
                        if not (text_range[0] <= addr < text_range[1]):
                            continue
                    elif name.startswith(_SKIP_PREFIXES):
                        continue
                    # First definition wins (some names appear in both tables).
                    out.setdefault(name, addr)
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to enumerate symbols for %s: %s", binary_path, e)
        return []

    return sorted(out.items(), key=lambda kv: kv[1])


# --------------------------------------------------------------------------- #
# Whole-program C -> per-function splitting
# --------------------------------------------------------------------------- #

# Matches a C function *definition* opening line: an identifier immediately
# followed by '(' and an eventual '{'. Captures the function name. Deliberately
# permissive: decompiler output is not clean C.
_FUNC_DEF_RE = re.compile(
    r"^[A-Za-z_][\w\s\*\(\),:<>\[\]&]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)


def split_c_functions(combined_c: str) -> dict[str, str]:
    """Best-effort split of whole-program C into ``{function_name: snippet}``.

    Walks the source tracking brace depth. When a ``name(...) {`` definition is
    seen at depth 0, everything up to the matching closing brace is captured for
    that name. Only top-level definitions are recorded (nested braces are
    balanced). This is heuristic — decompiler output is messy — and any function
    we cannot isolate simply won't get an individual snippet (callers fall back
    to other names or the combined source).
    """
    results: dict[str, str] = {}
    lines = combined_c.splitlines(keepends=True)
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _FUNC_DEF_RE.match(line)
        if m is None:
            i += 1
            continue
        name = m.group(1)
        # Accumulate from this line until braces balance back to zero.
        depth = 0
        opened = False
        chunk: list[str] = []
        j = i
        while j < n:
            cur = lines[j]
            chunk.append(cur)
            # Count braces, ignoring those in strings/char-literals crudely.
            stripped = _strip_c_literals(cur)
            depth += stripped.count("{")
            depth -= stripped.count("}")
            if "{" in stripped:
                opened = True
            if opened and depth <= 0:
                break
            j += 1
        snippet = "".join(chunk).rstrip() + "\n"
        # Keep the first definition of a given name.
        results.setdefault(name, snippet)
        i = j + 1
    return results


def _strip_c_literals(line: str) -> str:
    """Remove the contents of string/char literals and line comments.

    Crude but good enough to stop ``"}"`` inside a string from unbalancing the
    brace counter. Not a real lexer.
    """
    # Drop line comments.
    line = re.sub(r"//.*", "", line)
    # Blank out double-quoted strings and single-quoted chars.
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


# --------------------------------------------------------------------------- #
# Dockerized base
# --------------------------------------------------------------------------- #

class DockerizedDecompiler(Decompiler):
    """Base for decompilers run inside a Docker container.

    Subclasses set :attr:`image` (tag), :attr:`dockerfile` (file under
    ``docker/``), and implement :meth:`_container_decompile`, which runs the
    container against a mounted binary and returns whole-program C.
    """

    name = "dockerized"
    display_name = "Dockerized Decompiler"

    #: Docker image tag this backend runs, e.g. ``"decbench/retdec:latest"``.
    image: str = ""
    #: Dockerfile basename under ``docker/`` used to build :attr:`image`.
    dockerfile: str = ""
    #: Per-binary container timeout (seconds). Configurable via config below.
    container_timeout: float = 1800.0

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        if config is not None and config.binary_timeout_seconds:
            self.container_timeout = float(config.binary_timeout_seconds)

    # -- availability / build ------------------------------------------- #

    @staticmethod
    def _docker_bin() -> str | None:
        return shutil.which("docker")

    @classmethod
    def _image_present(cls, image: str) -> bool:
        docker = shutil.which("docker")
        if not docker or not image:
            return False
        try:
            proc = subprocess.run(
                [docker, "image", "inspect", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            return proc.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        """True iff the docker binary is present AND the image exists locally.

        Never builds the image (that would be a surprising, multi-minute side
        effect). Use ``decbench decompiler-build <name>`` to build it first.
        """
        return self._image_present(self.image)

    @classmethod
    def build_image(cls, no_cache: bool = False) -> int:
        """Build this backend's Docker image. Returns the ``docker build`` rc.

        Equivalent to ``docker build -f docker/<dockerfile> -t <image> .`` run
        from the repo root (the build context). Used by
        ``decbench decompiler-build <name>``.
        """
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        if not cls.image or not cls.dockerfile:
            raise RuntimeError(f"{cls.__name__} has no image/dockerfile configured")

        dockerfile_path = _DOCKER_DIR / cls.dockerfile
        if not dockerfile_path.is_file():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

        cmd = [
            docker, "build",
            "-f", str(dockerfile_path),
            "-t", cls.image,
        ]
        if no_cache:
            cmd.append("--no-cache")
        cmd.append(str(_DOCKER_DIR))  # build context = docker/ dir
        _l.info("Building %s: %s", cls.image, " ".join(cmd))
        proc = subprocess.run(cmd)
        return proc.returncode

    def get_version(self) -> str | None:
        # Image tag is the best version proxy without running the container.
        if not self.image:
            return None
        return self.image.rsplit(":", 1)[-1] if ":" in self.image else "latest"

    # -- decompilation -------------------------------------------------- #

    def _container_decompile(self, binary_path: Path, work_dir: Path) -> str:
        """Run the container and return whole-program C as a string.

        ``work_dir`` is a host temp dir bind-mounted into the container so the
        tool can write outputs there. Subclasses implement the tool-specific
        ``docker run`` invocation. Must raise on hard failure.
        """
        raise NotImplementedError

    def _run_docker(
        self,
        args: list[str],
        binary_path: Path,
        work_dir: Path,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``docker run`` with the binary mounted read-only at ``/in/<name>``
        and ``work_dir`` mounted read-write at ``/work``.

        ``args`` are appended after the image name (the container command). Use
        the placeholders ``/in/<binary_name>`` and ``/work`` in ``args``.
        """
        docker = self._docker_bin()
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        cmd = [
            docker, "run", "--rm",
            "-v", f"{binary_path.resolve()}:/in/{binary_path.name}:ro",
            "-v", f"{work_dir.resolve()}:/work",
            self.image,
            *args,
        ]
        _l.debug("docker run: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or self.container_timeout,
        )

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary inside the container and split into functions.

        Args:
            functions: optional ``(name, address)`` allowlist (addresses in ELF
                space). When None, all ELF-symbol functions are considered.
            function_names: optional name filter (restricts to a project's own
                source functions, like declib_dec).
            output_dir / progress_path: parity with the declib path; outputs are
                written to ``output_dir`` if given. ``progress_path`` is accepted
                for driver compatibility (whole-program tools run atomically, so
                there is no per-function checkpoint to write).
        """
        if not self.is_available():
            raise RuntimeError(
                f"Decompiler '{self.name}' is not available "
                f"(image '{self.image}' missing — run `decbench decompiler-build "
                f"{self.name}`)"
            )

        start = time.time()
        timed_out = False
        combined_c = ""
        error: str | None = None

        with tempfile.TemporaryDirectory(prefix=f"decbench_{self.name}_") as td:
            work_dir = Path(td)
            try:
                combined_c = self._container_decompile(binary_path, work_dir)
            except subprocess.TimeoutExpired as e:
                timed_out = True
                error = f"timeout after {self.container_timeout}s"
                _l.warning("%s timed out on %s: %s", self.name, binary_path, e)
            except Exception as e:  # noqa: BLE001
                error = str(e)
                _l.error("%s failed on %s: %s", self.name, binary_path, e)

        result = self._build_result(
            binary_path=binary_path,
            combined_c=combined_c,
            functions=functions,
            function_names=function_names,
            elapsed=time.time() - start,
            timed_out=timed_out,
            error=error,
            output_dir=output_dir,
        )

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            with contextlib.suppress(Exception):
                result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result

    def _build_result(
        self,
        binary_path: Path,
        combined_c: str,
        functions: list[tuple[str, int]] | None,
        function_names: set[str] | None,
        elapsed: float,
        timed_out: bool,
        error: str | None,
        output_dir: Path | None,
    ) -> DecompilationResult:
        """Assemble a :class:`DecompilationResult` from whole-program C."""
        # Determine the function set + addresses from the ELF symbol table so
        # addresses are ELF-file-space and match DWARF.
        if functions is not None:
            name_to_addr = {n: a for n, a in functions}
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))

        if function_names:
            filtered = {
                n: a for n, a in name_to_addr.items() if n in function_names
            }
            if filtered:
                name_to_addr = filtered

        snippets = split_c_functions(combined_c) if combined_c else {}

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        for name, addr in name_to_addr.items():
            code = snippets.get(name)
            if not code:
                failed.append(name)
                continue
            code = self._normalize_code(code)
            decompiled[name] = FunctionDecompilation(
                name=name,
                address=addr,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                line_mappings=[],
                variables=[],
                metadata={
                    "gotos": code.count("goto "),
                    "bools": code.count(" && ") + code.count(" || "),
                },
            )

        extra: dict[str, object] = {"via": "docker", "image": self.image}
        if error:
            extra["error"] = error
        if not combined_c:
            failed = list(name_to_addr.keys()) or ["all"]

        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=elapsed,
                timeout_occurred=timed_out,
                failed_functions=failed,
                extra=extra,
            ),
            functions=decompiled,
            combined_source=combined_c or None,
            output_dir=output_dir,
        )

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        """Discover functions from the ELF symbol table (no container needed)."""
        return elf_function_symbols(binary_path)

    def _normalize_code(self, code: str) -> str:
        """Hook for dialect normalization. Default identity."""
        return code


# --------------------------------------------------------------------------- #
# RetDec
# --------------------------------------------------------------------------- #

@register_decompiler("retdec")
class RetDecDecompiler(DockerizedDecompiler):
    """RetDec via a Docker image (``retdec-decompiler <binary> -o out.c``).

    Build: ``decbench decompiler-build retdec`` (slow — builds/downloads RetDec).
    """

    name = "retdec"
    display_name = "RetDec"
    image = "decbench/retdec:latest"
    dockerfile = "retdec.Dockerfile"

    def _container_decompile(self, binary_path: Path, work_dir: Path) -> str:
        # The image's ENTRYPOINT runs retdec-decompiler; emit C to /work/out.c.
        # retdec-decompiler writes <output>.c plus several sidecar files.
        proc = self._run_docker(
            args=[f"/in/{binary_path.name}", "-o", "/work/out.c"],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_c = work_dir / "out.c"
        if out_c.is_file():
            return out_c.read_text(errors="replace")
        # Some retdec builds write directly next to the input; nothing to read.
        raise RuntimeError(
            f"retdec produced no out.c (rc={proc.returncode}): "
            f"{proc.stderr[-500:] if proc.stderr else ''}"
        )


# --------------------------------------------------------------------------- #
# Reko
# --------------------------------------------------------------------------- #

@register_decompiler("reko")
class RekoDecompiler(DockerizedDecompiler):
    """Reko via a Docker image (.NET CLI ``reko --c <binary>``).

    Build: ``decbench decompiler-build reko`` (slow — builds Reko via dotnet).
    The image's helper script runs Reko headless and copies the generated
    ``*.c`` to ``/work/out.c``.
    """

    name = "reko"
    display_name = "Reko"
    image = "decbench/reko:latest"
    dockerfile = "reko.Dockerfile"

    def _container_decompile(self, binary_path: Path, work_dir: Path) -> str:
        # The image ships /opt/reko/decompile.sh which runs Reko on the binary
        # and consolidates the emitted C into /work/out.c.
        proc = self._run_docker(
            args=[f"/in/{binary_path.name}", "/work/out.c"],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_c = work_dir / "out.c"
        if out_c.is_file():
            return out_c.read_text(errors="replace")
        raise RuntimeError(
            f"reko produced no out.c (rc={proc.returncode}): "
            f"{proc.stderr[-500:] if proc.stderr else ''}"
        )


# --------------------------------------------------------------------------- #
# r2dec (native-first, Docker fallback)
# --------------------------------------------------------------------------- #

@register_decompiler("r2dec")
class R2DecDecompiler(DockerizedDecompiler):
    """radare2's pseudo-decompiler.

    radare2 is installed on this machine, so this backend prefers a **native**
    run via ``r2pipe``:

    * It tries the real r2dec plugin commands (``pd:d`` / ``pdd``) per function;
    * if the plugin is not installed, it falls back to radare2's **built-in**
      ``pdc`` pseudo-decompiler so the backend is still useful.

    Only if r2pipe / radare2 are unavailable does it fall back to the Docker
    image (``docker/r2dec.Dockerfile``), which builds radare2 + the r2dec plugin.
    """

    name = "r2dec"
    display_name = "r2dec"
    image = "decbench/r2dec:latest"
    dockerfile = "r2dec.Dockerfile"

    @staticmethod
    def _native_available() -> bool:
        if shutil.which("r2") is None and shutil.which("radare2") is None:
            return False
        try:
            import r2pipe  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def is_available(self) -> bool:
        """Available if native radare2+r2pipe OR the Docker image is present."""
        return self._native_available() or self._image_present(self.image)

    def get_version(self) -> str | None:
        if self._native_available():
            try:
                proc = subprocess.run(
                    [shutil.which("r2") or "radare2", "-v"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=20,
                )
                first = proc.stdout.splitlines()[0] if proc.stdout else ""
                m = re.search(r"radare2\s+(\S+)", first)
                if m:
                    return f"r2-{m.group(1)}"
            except Exception:  # noqa: BLE001
                pass
            return "native"
        return super().get_version()

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile natively via r2pipe when possible; else use the container."""
        if self._native_available():
            return self._decompile_native(
                binary_path,
                functions=functions,
                output_dir=output_dir,
                function_names=function_names,
            )
        return super().decompile_binary(
            binary_path,
            functions=functions,
            output_dir=output_dir,
            function_names=function_names,
            progress_path=progress_path,
        )

    # -- native r2pipe path --------------------------------------------- #

    def _decompile_native(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        output_dir: Path | None,
        function_names: set[str] | None,
    ) -> DecompilationResult:
        import r2pipe

        start = time.time()

        if functions is not None:
            name_to_addr = {n: a for n, a in functions}
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))
        if function_names:
            filtered = {
                n: a for n, a in name_to_addr.items() if n in function_names
            }
            if filtered:
                name_to_addr = filtered

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        used_cmd = "pdc"

        r = None
        try:
            r = r2pipe.open(
                str(binary_path),
                flags=["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"],
            )
            r.cmd("aaa")
            used_cmd = self._probe_decompile_cmd(r)
            for name, addr in name_to_addr.items():
                try:
                    code = self._decompile_one_native(r, used_cmd, addr)
                except Exception as e:  # noqa: BLE001
                    _l.debug("r2dec failed on %s: %s", name, e)
                    code = None
                if not code:
                    failed.append(name)
                    continue
                decompiled[name] = FunctionDecompilation(
                    name=name,
                    address=addr,
                    decompiled_code=code,
                    line_count=code.count("\n") + 1,
                    line_mappings=[],
                    variables=[],
                    metadata={
                        "gotos": code.count("goto "),
                        "bools": code.count(" && ") + code.count(" || "),
                    },
                )
        except Exception as e:  # noqa: BLE001
            _l.error("r2dec native run failed on %s: %s", binary_path, e)
            failed = list(name_to_addr.keys()) or ["all"]
        finally:
            if r is not None:
                with contextlib.suppress(Exception):
                    r.quit()

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                failed_functions=failed,
                extra={"via": "native", "command": used_cmd},
            ),
            functions=decompiled,
            output_dir=output_dir,
        )
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            with contextlib.suppress(Exception):
                result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")
        return result

    @staticmethod
    def _probe_decompile_cmd(r: object) -> str:
        """Pick the best available r2 decompile command.

        Prefers the real r2dec plugin (``pd:d``/``pdd``); falls back to the
        built-in ``pdc`` pseudo-decompiler when the plugin is absent.
        """
        for cmd in ("pd:d", "pdd"):
            try:
                out = r.cmd(f"{cmd} @ entry0")  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                out = ""
            if out and "install the plugin" not in out and "Cannot" not in out:
                return cmd
        return "pdc"

    @staticmethod
    def _decompile_one_native(r: object, cmd: str, addr: int) -> str | None:
        """Decompile one function at ``addr`` and return cleaned pseudo-C."""
        out = r.cmd(f"{cmd} @ {addr}")  # type: ignore[attr-defined]
        if not out:
            return None
        out = out.strip()
        if not out or "install the plugin" in out:
            return None
        return out


__all__ = [
    "DockerizedDecompiler",
    "RetDecDecompiler",
    "RekoDecompiler",
    "R2DecDecompiler",
    "elf_function_symbols",
    "split_c_functions",
]
