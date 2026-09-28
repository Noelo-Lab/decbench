"""Container-backed decompiler plugins.

Images are never built implicitly. Reko and RetDec split whole-program C;
r2dec consumes address-keyed records from its pinned image.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.limits import (
    BINARY_TIMEOUT_SECONDS,
    cleanup_docker_invocation,
    docker_memory_args,
    docker_tracking_args,
)
from decbench.decompilers.raw import common as raw_common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    VariableInfo,
)
from decbench.utils import binfmt

_l = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_DIR = _REPO_ROOT / "docker"

#: Back-compat aliases. The name filter, the section filter, and the
#: DWARF-target exemption all live in ``raw.common`` now — ONE rule for every
#: backend (see :func:`raw_common.should_skip_function`).
_SKIP_NAMES = raw_common.SKIP_NAMES
_SKIP_PREFIXES = raw_common.SKIP_PREFIXES
_elf_text_range = raw_common.elf_text_ranges


def elf_function_symbols(binary_path: Path) -> list[tuple[str, int]]:
    """Enumerate ``(name, address)`` for benchmarkable functions via ELF symbols.

    Addresses are in **ELF file space** (``st_value``), which matches DWARF and
    the native API decompilers. CRT/compiler helpers, import thunks, and
    anything outside the ``.text`` family are filtered out. Returned sorted by
    address.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except Exception as e:  # noqa: BLE001
        _l.debug("pyelftools unavailable: %s", e)
        return []

    text_range = raw_common.elf_text_ranges(binary_path)
    out: dict[str, int] = {}
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
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
                    if raw_common.should_skip_function(name, addr, text_range):
                        continue
                    out.setdefault(name, addr)
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to enumerate symbols for %s: %s", binary_path, e)
        return []

    return sorted(out.items(), key=lambda kv: kv[1])


_FUNC_DEF_RE = re.compile(
    r"^[A-Za-z_][\w\s\*\(\),:<>\[\]&]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)
_REKO_DEFINE_RE = re.compile(r"^define\s+(fn[0-9a-fA-F]+)\s*\{", re.MULTILINE)


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
        m = _FUNC_DEF_RE.match(line) or _REKO_DEFINE_RE.match(line)
        if m is None and i + 1 < n:
            pair = line + lines[i + 1]
            m = _FUNC_DEF_RE.match(pair) or _REKO_DEFINE_RE.match(pair)
        if m is None:
            i += 1
            continue
        name = m.group(1)
        depth = 0
        opened = False
        chunk: list[str] = []
        j = i
        while j < n:
            cur = lines[j]
            chunk.append(cur)
            stripped = _strip_c_literals(cur)
            depth += stripped.count("{")
            depth -= stripped.count("}")
            if "{" in stripped:
                opened = True
            if opened and depth <= 0:
                break
            j += 1
        snippet = "".join(chunk).rstrip() + "\n"
        results.setdefault(name, snippet)
        i = j + 1
    return results


def _reko_named_addresses(combined_c: str, snippets: dict[str, str]) -> dict[str, int]:
    addresses: dict[str, int] = {}
    for name, code in snippets.items():
        position = combined_c.find(code)
        if position < 0:
            continue
        prefix = combined_c[max(0, position - 512) : position]
        pattern = rf"(?m)^//\s*([0-9a-fA-F]{{8,16}}):[^\n]*\b{re.escape(name)}\s*\([^\n]*"
        matches = list(re.finditer(pattern, prefix))
        if matches and not prefix[matches[-1].end() :].strip():
            addresses[name] = int(matches[-1].group(1), 16)
    return addresses


def _strip_c_literals(line: str) -> str:
    """Remove the contents of string/char literals and line comments.

    Crude but good enough to stop ``"}"`` inside a string from unbalancing the
    brace counter. Not a real lexer.
    """
    line = re.sub(r"//.*", "", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


class DockerizedDecompiler(Decompiler):
    """Base for decompilers run inside a Docker container.

    Subclasses set :attr:`image` (tag), :attr:`dockerfile` (file under
    ``docker/``), and implement :meth:`_container_decompile`, which runs the
    container against a mounted binary and returns whole-program C.
    """

    name = "dockerized"
    display_name = "Dockerized Decompiler"

    image: str = ""
    dockerfile: str = ""
    container_timeout: float = float(BINARY_TIMEOUT_SECONDS)

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self.container_timeout = float(self.config.binary_timeout_seconds)

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

        Equivalent to ``docker build -f docker/<dockerfile> -t <image> docker/``
        (the ``docker/`` directory is the build context, so images can COPY the
        helper scripts living there). Used by ``decbench decompiler-build <name>``.
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
            docker,
            "build",
            "-f",
            str(dockerfile_path),
            "-t",
            cls.image,
        ]
        if no_cache:
            cmd.append("--no-cache")
        cmd.append(str(_DOCKER_DIR))
        _l.info("Building %s: %s", cls.image, " ".join(cmd))
        proc = subprocess.run(cmd)
        return proc.returncode

    def get_version(self) -> str | None:
        if not self.image:
            return None
        return self.image.rsplit(":", 1)[-1] if ":" in self.image else "latest"

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
        readonly_mounts: list[tuple[Path, str]] | None = None,
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
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            *docker_tracking_args(),
            *docker_memory_args(),
            "-v",
            f"{binary_path.resolve()}:/in/{binary_path.name}:ro",
            "-v",
            f"{work_dir.resolve()}:/work",
        ]
        for host_path, container_path in readonly_mounts or []:
            resolved = host_path.resolve()
            if not resolved.is_file():
                raise FileNotFoundError(f"Docker bind source not found: {resolved}")
            cmd.extend(["-v", f"{resolved}:{container_path}:ro"])
        cmd.extend([self.image, *args])
        _l.debug("docker run: %s", " ".join(cmd))
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.container_timeout,
            )
        except subprocess.TimeoutExpired:
            cleanup_docker_invocation(cmd)
            raise

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | set[int] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary inside the container and split into functions.

        Args:
            functions: optional ``(name, address)`` allowlist (addresses in ELF
                space). When None, all ELF-symbol functions are considered.
            function_names: optional name filter restricting the run to a
                project's own source functions.
            output_dir / progress_path: shared backend contract; outputs are
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
        function_names: set[str] | set[int] | None,
        elapsed: float,
        timed_out: bool,
        error: str | None,
        output_dir: Path | None,
    ) -> DecompilationResult:
        """Assemble a :class:`DecompilationResult` from whole-program C."""
        snippets = split_c_functions(combined_c) if combined_c else {}
        if functions is not None:
            name_to_addr = {n: a for n, a in functions}
        elif function_names and all(isinstance(a, int) for a in function_names):
            targets = {int(a) for a in function_names}
            info = binfmt.detect(binary_path)
            base = raw_common.elf_min_vaddr(binary_path) if info and info.fmt == "pe" else 0
            thumb_targets = (
                {target & ~1 for target in targets} if info and info.arch == "arm" else set()
            )
            reko_addresses = (
                _reko_named_addresses(combined_c, snippets) if self.name == "reko" else {}
            )
            name_to_addr = {}
            for name in snippets:
                match = re.fullmatch(r"(?:function_|fn)([0-9a-fA-F]+)", name)
                if match is None and name not in reko_addresses:
                    continue
                address = int(match.group(1), 16) if match else reko_addresses[name]
                candidates = (address, address + base) if base else (address,)
                if any(
                    candidate in targets or candidate & ~1 in thumb_targets
                    for candidate in candidates
                ):
                    name_to_addr[name] = address
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))
            if function_names:
                name_to_addr = {n: a for n, a in name_to_addr.items() if n in function_names}

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

        extra: dict[str, object] = {
            "via": "docker",
            "image": self.image,
            "slice_scoped": bool(function_names or functions),
        }
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

    def _normalize_code(self, code: str) -> str:
        """Hook for dialect normalization. Default identity."""
        return code


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
        proc = self._run_docker(
            args=[f"/in/{binary_path.name}", "-o", "/work/out.c"],
            binary_path=binary_path,
            work_dir=work_dir,
        )
        out_c = work_dir / "out.c"
        if out_c.is_file():
            return out_c.read_text(errors="replace")
        raise RuntimeError(
            f"retdec produced no out.c (rc={proc.returncode}): "
            f"{proc.stderr[-500:] if proc.stderr else ''}"
        )


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


_R2_ENTRY_NAMES = frozenset({"entry0", "entry1", "entry.init0", "entry.fini0", "entry.preinit0"})

_C_KEYWORDS = frozenset({"if", "while", "for", "switch", "return", "do", "else", "sizeof", "case"})

# Tolerates both common r2 pseudo-name spellings.
_R2_DEF_RE = re.compile(r"\b([A-Za-z_][\w.]*)\s*\([^;{}]*?\)\s*\{")
_R2_DRIVER_SCHEMA_VERSION = 1
_R2_DRIVER_CONTAINER_PATH = "/opt/r2dec-decompile.py"


def _r2_int(value: Any, default: int | None = None) -> int | None:
    """Best-effort integer conversion for radare2's mixed JSON scalars."""
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _r2_inferred_variables(
    code: str,
    function_name: str,
    line_mappings: list[Any],
) -> list[VariableInfo]:
    """Join uniquely bound C variables to native r2 render-line addresses."""
    try:
        from decbench.metrics.type_match import parse_c_variables
        from decbench.metrics.variable_features import variable_occurrence_lines

        variables = parse_c_variables(code, function_name)
        occurrence_lines = variable_occurrence_lines(
            code,
            function_name,
            (variable.name for variable in variables),
            require_exact_function_name=True,
        )
    except Exception:  # noqa: BLE001
        return []
    line_addresses = {
        int(mapping.line_number): {int(address) for address in mapping.addresses}
        for mapping in line_mappings
    }
    out: list[VariableInfo] = []
    for variable in variables:
        lines = list(occurrence_lines.get(variable.name, ())) if variable.name else []
        out.append(
            variable.model_copy(
                update={
                    "line_numbers": lines,
                    "addresses": sorted(
                        {
                            address
                            for line_number in lines
                            for address in line_addresses.get(line_number, set())
                        }
                    ),
                }
            )
        )
    return out


def _r2_is_import(name: str) -> bool:
    """Whether an r2 function flag names an import / PLT / reloc stub."""
    return (
        name.startswith("sym.imp.")
        or name.startswith("imp.")
        or name.startswith("reloc.")
        or ".imp." in name
    )


def _r2_bare_name(name: str) -> str:
    """Strip r2's flag namespace (``sym.``/``fcn.``/``loc.``) to a bare ident."""
    return name.rsplit(".", 1)[-1] if name else name


#: Back-compat aliases for what used to be r2dec-only logic. The DWARF-target
#: exemption these implemented — a function whose address is one the driver
#: asked for is a VERIFIED real function and is kept whatever section it landed
#: in — is now part of the shared filter, so every backend gets it.
_addr_targets_of = raw_common.addr_targets_of
_skip_r2_function = raw_common.should_skip_function


def _func_ident_in_code(code: str) -> str | None:
    """The identifier of the first top-level function definition in ``code``.

    Block comments (``/* ... */`` — r2dec prefixes its output with a
    ``/* r2dec pseudo code output ... */`` banner), line comments, and
    preprocessor lines (r2dec emits ``#include`` / ``#define`` macros) are
    stripped first so none of them is mistaken for the signature, and C keywords
    are skipped so a leading ``if (...) {`` is not either. Returns ``None`` when
    no definition opener is found.
    """
    stripped = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    stripped = re.sub(r"//.*", "", stripped)
    stripped = re.sub(r"(?m)^[ \t]*#.*$", "", stripped)
    for m in _R2_DEF_RE.finditer(stripped):
        ident = m.group(1)
        if ident not in _C_KEYWORDS:
            return ident
    return None


@register_decompiler("r2dec")
class R2DecDecompiler(DockerizedDecompiler):
    """radare2's r2dec decompiler (address-keyed, stripped-binary ready).

    Function discovery comes from radare2's OWN analysis (``aaa`` + ``aflj``),
    not the ELF symbol table, so it works on fully STRIPPED ELF/PE and on ARM
    firmware. Each function's start is normalized to ELF-file space
    (``r2_addr - r2_baddr + elf_min_vaddr``) so it matches DWARF ``low_pc`` and
    the benchmark driver's address-based function filter — radare2 loads a binary
    at its own ``baddr`` (the ELF min PT_LOAD vaddr / PE ImageBase), which equals
    ``elf_min_vaddr``, so an r2 function address is already ELF-file space.

    The ``function_names`` filter accepts a set of **ints** (ELF-file-space
    addresses — the benchmark driver's DWARF ``low_pc`` set, matched Thumb-bit
    tolerant) or a set of **strs** (legacy name matching).
    """

    name = "r2dec"
    display_name = "r2dec"
    image = "decbench/r2dec:6.2.0"
    dockerfile = "r2dec.Dockerfile"

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary through the real r2dec ``pdd`` command."""
        return self._decompile_docker(
            binary_path, functions, output_dir, function_names, progress_path
        )

    @staticmethod
    def _narrow(
        discovered: list[tuple[str, int, int]],
        function_names: set[int] | set[str] | None,
        binary_name: str,
    ) -> list[tuple[str | None, int, int, str]]:
        """Restrict discovered functions to the requested set.

        ``function_names`` may hold ELF-file-space ADDRESSES (ints — the driver's
        DWARF ``low_pc`` filter, matched Thumb-bit tolerant) or NAMES (strs,
        legacy). Returns ``(label, file_addr, r2_addr, r2_flag)`` tuples where
        ``label`` is the requested name for the str path (so the result keys by
        it) and ``None`` otherwise (the code identifier becomes the key). Falls
        back to everything if nothing matched, so a filter mismatch never yields
        an empty result.
        """
        all_targets: list[tuple[str | None, int, int, str]] = [
            (None, fa, raw, nm) for (nm, fa, raw) in discovered
        ]
        if not function_names:
            return all_targets
        addr_targets = {
            int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)
        }
        name_targets = {str(x) for x in function_names if isinstance(x, str)}
        if addr_targets:
            kept: list[tuple[str | None, int, int, str]] = [
                (None, fa, raw, nm)
                for (nm, fa, raw) in discovered
                if raw_common._addr_matches(fa, addr_targets)
            ]
            if kept:
                _l.debug(
                    "r2dec: narrowed %d/%d functions to source set for %s",
                    len(kept),
                    len(discovered),
                    binary_name,
                )
                return kept
            return all_targets
        if name_targets:
            named: list[tuple[str | None, int, int, str]] = []
            for nm, fa, raw in discovered:
                bare = _r2_bare_name(nm)
                match = nm if nm in name_targets else (bare if bare in name_targets else None)
                if match is not None:
                    named.append((match, fa, raw, nm))
            return named or all_targets
        return all_targets

    @staticmethod
    def _make_function(
        r2_flag: str,
        file_addr: int,
        code: str,
        label: str | None,
        provenance: dict[str, Any] | None = None,
        *,
        r2_addr: int | None = None,
        baddr: int = 0,
        elf_base: int = 0,
    ) -> FunctionDecompilation | None:
        """Build a :class:`FunctionDecompilation`, keeping ``.name`` equal to the
        identifier that appears in ``decompiled_code``.

        The run driver relabels a stripped-binary decompilation by address,
        rewriting ``fd.name`` in BOTH the code and the function key to the DWARF
        name — which only works if ``fd.name`` is the identifier actually used in
        the code. So we adopt the code's own identifier (or, on the legacy name
        path, rewrite the code to the requested ``label``).
        """
        code = (code or "").strip()
        if not code:
            return None
        provenance = provenance or {}
        function_raw = _r2_int(r2_addr, _r2_int(provenance.get("addr"), file_addr))
        function_size = _r2_int(provenance.get("size"), 0) or 0
        is_thumb = bool(provenance.get("is_thumb"))
        normalized_start = (
            (function_raw & ~1) if is_thumb and function_raw is not None else function_raw
        )

        def evidence_address(value: Any) -> int | None:
            raw_address = _r2_int(value)
            if raw_address is None:
                return None
            normalized = raw_address & ~1 if is_thumb else raw_address
            if normalized_start is not None and normalized < normalized_start:
                return None
            if (
                function_size > 0
                and normalized_start is not None
                and normalized >= normalized_start + function_size
            ):
                return None
            return normalized - baddr + elf_base

        code_ident = _func_ident_in_code(code)
        final = label or code_ident or r2_flag
        if code_ident and code_ident != final:
            code = re.sub(r"\b" + re.escape(code_ident) + r"\b", final, code)
        line_count = code.count("\n") + 1
        line_to_addresses: dict[int, set[int]] = {}
        for mapping in provenance.get("line_mappings") or []:
            if not isinstance(mapping, dict):
                continue
            line_number = _r2_int(mapping.get("line_number"), 0) or 0
            if not 1 <= line_number <= line_count:
                continue
            for value in mapping.get("addresses") or []:
                address = evidence_address(value)
                if address is not None:
                    line_to_addresses.setdefault(line_number, set()).add(address)
        line_mappings = raw_common.merge_line_addresses(line_to_addresses)

        variables: list[VariableInfo] = []
        for record in provenance.get("variables") or []:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if not name:
                continue
            line_numbers = sorted(
                {
                    line_number
                    for value in record.get("line_numbers") or []
                    if 1 <= (line_number := (_r2_int(value, 0) or 0)) <= line_count
                }
            )
            addresses = sorted(
                {
                    address
                    for value in record.get("addresses") or []
                    if (address := evidence_address(value)) is not None
                }
            )
            raw_size = _r2_int(record.get("size"))
            size = raw_size if raw_size is not None and raw_size > 0 else None
            raw_arg_index = _r2_int(record.get("arg_index"))
            arg_index = raw_arg_index if raw_arg_index is not None and raw_arg_index >= 0 else None
            kind = "arg" if record.get("kind") == "arg" else "stack"
            variables.append(
                VariableInfo(
                    name=name,
                    type=str(record.get("type") or ""),
                    stack_offset=_r2_int(record.get("stack_offset")),
                    size=size,
                    kind=kind,
                    arg_index=arg_index if kind == "arg" else None,
                    line_numbers=line_numbers,
                    addresses=addresses,
                )
            )
        if not variables and line_mappings:
            variables = _r2_inferred_variables(code, final, line_mappings)
        output_address = file_addr & ~1 if is_thumb else file_addr
        return FunctionDecompilation(
            name=final,
            address=output_address,
            decompiled_code=code,
            line_count=line_count,
            line_mappings=line_mappings,
            variables=variables,
            metadata=raw_common.extract_metrics(code),
        )

    def _write_artifacts(
        self,
        result: DecompilationResult,
        output_dir: Path | None,
        binary_path: Path,
    ) -> None:
        if output_dir is None:
            return
        output_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(Exception):
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
        with contextlib.suppress(Exception):
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

    def _decompile_docker(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        output_dir: Path | None,
        function_names: set[int] | set[str] | None,
        progress_path: Path | None,
    ) -> DecompilationResult:
        if not self._image_present(self.image):
            raise RuntimeError(
                f"Decompiler '{self.name}' docker image '{self.image}' missing — "
                f"run `decbench decompiler-build {self.name}`"
            )
        start = time.time()
        elf_base = raw_common.elf_min_vaddr(binary_path)
        text_range = raw_common.elf_text_ranges(binary_path)

        addr_targets: list[int] | None = None
        ints: set[int] = set()
        if function_names:
            ints |= {
                int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)
            }
        if functions:
            ints |= {int(a) for (_n, a) in functions}
        if ints:
            addr_targets = sorted(ints)

        entries: list[dict[str, Any]] = []
        error: str | None = None
        timed_out = False
        with tempfile.TemporaryDirectory(prefix=f"decbench_{self.name}_") as td:
            work_dir = Path(td)
            targets_arg = "NONE"
            if addr_targets is not None:
                (work_dir / "targets.json").write_text(json.dumps(addr_targets))
                targets_arg = "/work/targets.json"
            try:
                proc = self._run_docker(
                    args=[f"/in/{binary_path.name}", "/work/out.json", targets_arg],
                    binary_path=binary_path,
                    work_dir=work_dir,
                    readonly_mounts=[
                        (_DOCKER_DIR / "r2dec-decompile.py", _R2_DRIVER_CONTAINER_PATH)
                    ],
                )
                out_json = work_dir / "out.json"
                if out_json.is_file():
                    payload = json.loads(out_json.read_text() or "{}")
                    if not isinstance(payload, dict):
                        raise RuntimeError("r2dec container returned a legacy driver payload")
                    schema_version = payload.get("schema_version")
                    if (
                        type(schema_version) is not int
                        or schema_version != _R2_DRIVER_SCHEMA_VERSION
                    ):
                        raise RuntimeError(
                            "r2dec container driver schema mismatch: "
                            f"expected {_R2_DRIVER_SCHEMA_VERSION}, got {schema_version}"
                        )
                    raw_entries = payload.get("functions")
                    if not isinstance(raw_entries, list) or not all(
                        isinstance(entry, dict) for entry in raw_entries
                    ):
                        raise RuntimeError("r2dec container returned malformed function records")
                    driver_command = payload.get("command")
                    if driver_command != "pdd":
                        raise RuntimeError(
                            f"r2dec container returned invalid command: {driver_command}"
                        )
                    entries = raw_entries
                else:
                    error = (
                        f"container produced no out.json (rc={proc.returncode}): "
                        f"{(proc.stderr or '')[-400:]}"
                    )
            except subprocess.TimeoutExpired:
                timed_out = True
                error = f"timeout after {self.container_timeout}s"
                _l.warning("%s docker timed out on %s", self.name, binary_path)
            except Exception as e:  # noqa: BLE001
                error = str(e)
                _l.error("%s docker failed on %s: %s", self.name, binary_path, e)

        by_addr: dict[int, tuple[str, dict[str, Any]]] = {}
        discovered: list[tuple[str, int, int]] = []
        filter_addrs = _addr_targets_of(function_names)
        for entry in entries:
            raw = entry.get("addr")
            if raw is None:
                continue
            b = int(entry.get("baddr") or 0)
            file_addr = int(raw) - b + elf_base
            nm = entry.get("name") or ""
            if _r2_is_import(nm) or nm in _R2_ENTRY_NAMES:
                continue
            if _skip_r2_function(_r2_bare_name(nm), file_addr, text_range, filter_addrs):
                continue
            by_addr[file_addr] = (nm, entry)
            discovered.append((nm, file_addr, int(raw)))
        discovered.sort(key=lambda t: t[1])
        targets = self._narrow(discovered, function_names, binary_path.name)

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        for label, file_addr, raw, r2_flag in targets:
            _nm, entry = by_addr.get(file_addr, (r2_flag, {}))
            entry_baddr = _r2_int(entry.get("baddr"), 0) or 0
            fd = self._make_function(
                r2_flag,
                file_addr,
                str(entry.get("code") or ""),
                label,
                entry,
                r2_addr=_r2_int(entry.get("addr"), raw),
                baddr=entry_baddr,
                elf_base=elf_base,
            )
            if fd is None:
                failed.append(label or _r2_bare_name(r2_flag))
            else:
                decompiled[fd.name] = fd
        if not entries and not decompiled:
            failed = failed or ["all"]

        extra: dict[str, Any] = {
            "via": "docker",
            "command": "pdd",
            "image": self.image,
        }
        if error:
            extra["error"] = error
        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                timeout_occurred=timed_out,
                failed_functions=failed,
                extra=extra,
            ),
            functions=decompiled,
            output_dir=output_dir,
        )
        raw_common.dump_progress(progress_path, result)
        self._write_artifacts(result, output_dir, binary_path)
        return result


__all__ = [
    "DockerizedDecompiler",
    "RetDecDecompiler",
    "RekoDecompiler",
    "R2DecDecompiler",
    "elf_function_symbols",
    "split_c_functions",
]
