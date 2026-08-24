"""Container-backed and external-tool decompiler plugins.

This module hosts decompilers that decbench does **not** drive through declib,
because they ship as standalone CLIs rather than Python libraries:

- **Reko** (``reko``) — .NET decompiler, run inside a Docker image.
- **RetDec** (``retdec``) — LLVM-based decompiler, run inside a Docker image.
- **r2dec** (``r2dec``) — radare2's r2dec decompiler. Discovers functions from
  radare2's OWN analysis (``aaa`` + ``aflj``, so it works on fully STRIPPED
  ELF/PE and ARM firmware), normalizes addresses to ELF-file space, and
  decompiles each function with the r2dec ``pdd`` command — falling back to the
  built-in ``pdc`` pseudo-decompiler when the r2dec plugin is absent. It picks,
  in order, native-with-plugin > the ``decbench/r2dec`` Docker image (real
  r2dec built from source; the host's packaged r2 usually lacks the dev headers
  to build the plugin natively) > native ``pdc``. Unlike the whole-program
  RetDec/Reko path, r2dec does NOT go through the ELF symbol table or
  ``split_c_functions`` — its discovery and per-function decompile are
  symbol-free and address-keyed, matching how the benchmark driver hands it a
  stripped binary + a set of DWARF ``low_pc`` addresses.

Common design (:class:`DockerizedDecompiler`):
    The container is run with the target binary bind-mounted **read-only**; the
    decompiler emits whole-program C, which we then split into per-function
    snippets. Function *names and addresses* come from the binary's ELF symbol
    table (via pyelftools), so addresses live in **ELF file space** and line up
    with DWARF and the rest of decbench — the same convention declib_dec uses.

    Reko and RetDec do not expose stack variables / line mappings uniformly, so
    those fields remain empty for their results. r2dec attaches ``pddj`` line
    offsets plus ``afv*`` variable metadata and access addresses when available.
    The metrics still degrade gracefully when optional provenance is absent.

Images are **not** auto-built. ``is_available()`` only reports whether the image
already exists locally; build it explicitly with ``decbench decompiler-build
<name>`` (which calls :meth:`DockerizedDecompiler.build_image`).
"""

from __future__ import annotations

import contextlib
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common as raw_common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    VariableInfo,
)

_l = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_DIR = _REPO_ROOT / "docker"

_SKIP_NAMES = frozenset(
    {
        "_start",
        "__libc_start_main",
        "__libc_csu_init",
        "__libc_csu_fini",
        "_init",
        "_fini",
        "__do_global_dtors_aux",
        "register_tm_clones",
        "deregister_tm_clones",
        "frame_dummy",
        "__libc_start_call_main",
        "_dl_relocate_static_pie",
        "__gmon_start__",
        "__stack_chk_fail",
    }
)

_SKIP_PREFIXES = ("thunk_", "j_", "__imp_", ".plt", "_dl_")


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
                    out.setdefault(name, addr)
    except Exception as e:  # noqa: BLE001
        _l.debug("Failed to enumerate symbols for %s: %s", binary_path, e)
        return []

    return sorted(out.items(), key=lambda kv: kv[1])


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
    container_timeout: float = 1800.0

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        if config is not None and config.binary_timeout_seconds:
            self.container_timeout = float(config.binary_timeout_seconds)

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
            "-v",
            f"{binary_path.resolve()}:/in/{binary_path.name}:ro",
            "-v",
            f"{work_dir.resolve()}:/work",
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
        if functions is not None:
            name_to_addr = {n: a for n, a in functions}
        else:
            name_to_addr = dict(elf_function_symbols(binary_path))

        if function_names:
            filtered = {n: a for n, a in name_to_addr.items() if n in function_names}
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

# Tolerates both r2 pseudo-name spellings (``fcn.00003bed`` from ``pdc`` and
# ``fcn_00003bed`` from ``pdd``). The parameter list is matched non-greedily so
# an ``ident (...)`` inside a comment cannot swallow text up to the real ``) {``.
_R2_DEF_RE = re.compile(r"\b([A-Za-z_][\w.]*)\s*\([^;{}]*?\)\s*\{")


def _r2_int(value: Any, default: int | None = None) -> int | None:
    """Best-effort integer conversion for radare2's mixed JSON scalars."""
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _r2_json_lines(payload: Any) -> tuple[str, list[dict[str, Any]]] | None:
    """Turn r2dec ``pddj`` rows into code and same-render line evidence."""
    rows = payload.get("lines") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        return None

    rendered: list[tuple[str, int | None]] = []
    for row in rows:
        if not isinstance(row, dict) or "str" not in row:
            continue
        text = str(row.get("str") or "")
        pieces = text.splitlines() or [""]
        offset = _r2_int(row.get("offset"))
        rendered.extend((piece, offset) for piece in pieces)
    if not rendered:
        return None

    while rendered and not rendered[0][0].strip():
        rendered.pop(0)
    while rendered and not rendered[-1][0].strip():
        rendered.pop()
    if not rendered:
        return None

    code = "\n".join(text for text, _offset in rendered)
    mappings = [
        {"line_number": line_number, "addresses": [offset]}
        for line_number, (_text, offset) in enumerate(rendered, 1)
        if offset is not None
    ]
    return code, mappings


def _r2_json_annotations(payload: Any) -> tuple[str, list[dict[str, Any]]] | None:
    """Turn radare2 ``pdcj`` code annotations into per-line offsets."""
    if not isinstance(payload, dict):
        return None
    raw_code = str(payload.get("code") or "")
    code = raw_code.strip()
    annotations = payload.get("annotations")
    if not code or not isinstance(annotations, list):
        return None
    code_start = raw_code.find(code)
    mappings: list[dict[str, Any]] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        offset = _r2_int(annotation.get("offset"))
        position = _r2_int(annotation.get("start"))
        if offset is None or position is None or position < code_start:
            continue
        adjusted = min(position - code_start, len(code))
        mappings.append(
            {
                "line_number": code.count("\n", 0, adjusted) + 1,
                "addresses": [offset],
            }
        )
    return code, mappings


def _r2_cmdj(r: Any, command: str, default: Any) -> Any:
    """Run one JSON command without letting optional provenance break output."""
    try:
        payload = r.cmdj(command)
    except Exception:  # noqa: BLE001
        return default
    return default if payload is None else payload


def _r2_variable_records(
    r: Any,
    addr: int,
    line_mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect r2's variable metadata and read/write instruction addresses."""
    metadata = _r2_cmdj(r, f"afvj @ {addr}", {})
    if not isinstance(metadata, dict):
        return []

    accesses: dict[str, set[int]] = {}
    for command in ("afvRj", "afvWj"):
        records = _r2_cmdj(r, f"{command} @ {addr}", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if not name:
                continue
            for value in record.get("addrs") or []:
                address = _r2_int(value)
                if address is not None:
                    accesses.setdefault(name, set()).add(address)

    signature = _r2_cmdj(r, f"afcfj @ {addr}", [])
    signature_args: list[str] = []
    if isinstance(signature, list) and signature and isinstance(signature[0], dict):
        signature_args = [
            str(arg.get("name") or "")
            for arg in signature[0].get("args") or []
            if isinstance(arg, dict) and arg.get("name")
        ]
    lines_by_address: dict[int, set[int]] = {}
    for mapping in line_mappings:
        line_number = _r2_int(mapping.get("line_number"))
        if line_number is None:
            continue
        for value in mapping.get("addresses") or []:
            address = _r2_int(value)
            if address is not None:
                lines_by_address.setdefault(address, set()).add(line_number)

    ordered: list[tuple[str, dict[str, Any]]] = []
    for group in ("reg", "sp", "bp"):
        records = metadata.get(group) or []
        if not isinstance(records, list):
            continue
        ordered.extend((group, record) for record in records if isinstance(record, dict))

    fallback_args = list(
        dict.fromkeys(
            str(record.get("name") or "")
            for group, record in ordered
            if (group == "reg" or str(record.get("kind") or "") == "arg") and record.get("name")
        )
    )
    signature_positions = {name: index for index, name in enumerate(signature_args)}
    arg_positions = {
        name: signature_positions.get(name, index) for index, name in enumerate(fallback_args)
    }

    variables: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for group, record in ordered:
        name = str(record.get("name") or "")
        if not name:
            continue
        ref = record.get("ref")
        stack_offset = _r2_int(ref.get("offset")) if isinstance(ref, dict) else None
        identity = (group, name, stack_offset)
        if identity in seen:
            continue
        seen.add(identity)
        raw_addresses = sorted(accesses.get(name, set()))
        is_arg = name in arg_positions
        variables.append(
            {
                "name": name,
                "type": str(record.get("type") or ""),
                "stack_offset": stack_offset,
                "size": _r2_int(record.get("size")),
                "kind": "arg" if is_arg else "stack",
                "arg_index": arg_positions.get(name),
                "line_numbers": sorted(
                    {
                        line_number
                        for address in raw_addresses
                        for line_number in lines_by_address.get(address, set())
                    }
                ),
                "addresses": raw_addresses,
            }
        )
    return variables


def _r2_inferred_variables(
    code: str,
    function_name: str,
    line_mappings: list[Any],
) -> list[VariableInfo]:
    """Join code-parsed variables to native r2 render-line addresses."""
    try:
        from decbench.metrics.type_match import parse_c_variables

        variables = parse_c_variables(code, function_name)
    except Exception:  # noqa: BLE001
        return []
    line_addresses = {
        int(mapping.line_number): {int(address) for address in mapping.addresses}
        for mapping in line_mappings
    }
    code_lines = code.splitlines()
    out: list[VariableInfo] = []
    for variable in variables:
        if not variable.name:
            out.append(variable)
            continue
        token = re.compile(r"\b" + re.escape(variable.name) + r"\b")
        lines = sorted(
            line_number for line_number, text in enumerate(code_lines, 1) if token.search(text)
        )
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


def _addr_targets_of(function_names: set[int] | set[str] | None) -> set[int]:
    """The int (ELF-file-space) addresses in the driver's function filter."""
    if not function_names:
        return set()
    return {int(x) for x in function_names if isinstance(x, int) and not isinstance(x, bool)}


def _skip_r2_function(
    bare_name: str,
    file_addr: int,
    text_range: tuple[int, int] | None,
    addr_targets: set[int] | None,
) -> bool:
    """Whether to drop an r2-discovered function, honouring the source targets.

    A function whose address is one of ``addr_targets`` (the DWARF ``low_pc``
    source functions the driver asked for) is a VERIFIED real function and is
    always kept: the ``.text`` heuristic behind :func:`should_skip_function`
    misfires on binaries with the code split across multiple executable
    sections (e.g. u-boot's tiny ``.text`` + 486 KB ``.text_rest``, freertos),
    where the real functions live outside the one detected ``.text`` and would
    otherwise be dropped — the exact reason r2dec scored 0 on those ARM targets.
    Non-target functions still go through the normal filter.
    """
    if addr_targets and raw_common._addr_matches(file_addr, addr_targets):
        return False
    return raw_common.should_skip_function(bare_name, file_addr, text_range)


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

    Three execution paths, tried in this order:

    1. **native pdd** — radare2 + the r2dec plugin installed on the host;
    2. **docker pdd** — the ``decbench/r2dec`` image (real r2dec built from
       source; the host's packaged r2 usually lacks the dev headers to build the
       plugin natively);
    3. **native pdc** — radare2's built-in pseudo-decompiler (always available
       when r2 is installed, but its asm-like output rarely parses for GED).

    The ``function_names`` filter accepts a set of **ints** (ELF-file-space
    addresses — the benchmark driver's DWARF ``low_pc`` set, matched Thumb-bit
    tolerant) or a set of **strs** (legacy name matching).
    """

    name = "r2dec"
    display_name = "r2dec"
    image = "decbench/r2dec:latest"
    dockerfile = "r2dec.Dockerfile"

    _R2_FLAGS = ["-2", "-e", "bin.relocs.apply=true", "-e", "scr.color=0"]

    @staticmethod
    def _native_available() -> bool:
        if shutil.which("r2") is None and shutil.which("radare2") is None:
            return False
        try:
            import r2pipe  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    def _native_plugin_available() -> bool:
        """True iff radare2's r2dec plugin (``pdd``) is installed natively.

        Scans the user + system radare2 plugin dirs for the r2dec core plugin
        (``*pdd*`` / ``*r2dec*``) so the real decompiler can be preferred over the
        built-in ``pdc`` without opening r2. A false negative is harmless: the
        native path's command probe still upgrades to ``pdd`` if it is present.
        """
        dirs = [os.path.expanduser("~/.local/share/radare2/plugins")]
        try:
            proc = subprocess.run(
                [shutil.which("r2") or "radare2", "-H", "R2_LIBR_PLUGINS"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            sysdir = (proc.stdout or "").strip()
            if sysdir:
                dirs.append(sysdir)
        except Exception:  # noqa: BLE001
            dirs.extend(["/usr/lib/radare2", "/usr/local/lib/radare2"])
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            for pat in ("*pdd*", "*r2dec*"):
                if glob.glob(os.path.join(d, "**", pat), recursive=True):
                    return True
        return False

    def is_available(self) -> bool:
        """Available if native radare2+r2pipe OR the Docker image is present."""
        return self._native_available() or self._image_present(self.image)

    def _select_path(self) -> str:
        """Choose the execution path: ``"native"`` or ``"docker"``.

        Preference: native-with-plugin (real r2dec, no container overhead) >
        docker (real r2dec in a container) > native-without-plugin (``pdc``). The
        native path probes ``pdd``/``pdc`` itself, so this only decides host vs
        container.
        """
        native = self._native_available()
        if native and self._native_plugin_available():
            return "native"
        if self._image_present(self.image):
            return "docker"
        if native:
            return "native"
        return "docker"

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
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a binary via the real r2dec (native or docker) or ``pdc``."""
        if self._select_path() == "docker":
            return self._decompile_docker(
                binary_path, functions, output_dir, function_names, progress_path
            )
        return self._decompile_native(
            binary_path, functions, output_dir, function_names, progress_path
        )

    @staticmethod
    def _discover(
        r: Any,
        elf_base: int,
        text_range: tuple[int, int] | None,
        baddr: int,
        addr_targets: set[int] | None = None,
    ) -> list[tuple[str, int, int]]:
        """``(r2_flag_name, file_addr, r2_addr)`` for benchmarkable functions.

        Uses radare2's ``aflj`` (function list). ``file_addr`` is ELF-file space
        (``r2_addr - baddr + elf_base``). Imports/PLT/reloc stubs, the entrypoint
        alias, CRT helpers, and anything outside ``.text`` are dropped — EXCEPT a
        function whose address is one of ``addr_targets`` (the driver's DWARF
        ``low_pc`` source set), which is a verified real function and is kept
        regardless of the ``.text`` heuristic (see :func:`_skip_r2_function`).
        """
        funcs = r.cmdj("aflj") or []
        out: list[tuple[str, int, int]] = []
        for fn in funcs:
            name = fn.get("name") or ""
            raw = fn.get("addr")
            if raw is None:
                raw = fn.get("offset")
            if not name or raw is None:
                continue
            if _r2_is_import(name) or name in _R2_ENTRY_NAMES:
                continue
            raw = int(raw)
            file_addr = raw - baddr + elf_base
            if _skip_r2_function(_r2_bare_name(name), file_addr, text_range, addr_targets):
                continue
            out.append((name, file_addr, raw))
        out.sort(key=lambda t: t[1])
        return out

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

        def _evidence_address(value: Any) -> int | None:
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
                address = _evidence_address(value)
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
                    if (address := _evidence_address(value)) is not None
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

    def _make_result(
        self,
        binary_path: Path,
        decompiled: dict[str, FunctionDecompilation],
        failed: list[str],
        elapsed: float,
        via: str,
        cmd: str,
        output_dir: Path | None,
        *,
        partial: bool = False,
        timed_out: bool = False,
        error: str | None = None,
    ) -> DecompilationResult:
        extra: dict[str, Any] = {"via": via, "command": cmd}
        if via == "docker":
            extra["image"] = self.image
        if partial:
            extra["partial"] = True
        if error:
            extra["error"] = error
        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=elapsed,
                timeout_occurred=timed_out,
                failed_functions=list(failed),
                extra=extra,
            ),
            functions=dict(decompiled),
            output_dir=output_dir,
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

    def _decompile_native(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None,
        output_dir: Path | None,
        function_names: set[int] | set[str] | None,
        progress_path: Path | None,
    ) -> DecompilationResult:
        import r2pipe

        start = time.time()
        elf_base = raw_common.elf_min_vaddr(binary_path)
        text_range = raw_common.elf_text_range(binary_path)
        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        used_cmd = "pdc"
        targets: list[tuple[str | None, int, int, str]] = []

        def _dump() -> None:
            common_res = self._make_result(
                binary_path,
                decompiled,
                failed,
                time.time() - start,
                "native",
                used_cmd,
                output_dir,
                partial=True,
            )
            raw_common.dump_progress(progress_path, common_res)

        r = None
        try:
            r = r2pipe.open(str(binary_path), flags=self._R2_FLAGS)
            r.cmd("aaa")
            baddr = self._r2_baddr(r)
            used_cmd = self._probe_decompile_cmd(r)
            if functions is not None:
                for name, fa in functions:
                    raw = int(fa) - elf_base + baddr
                    with contextlib.suppress(Exception):
                        r.cmd(f"af @ {raw}")
                    targets.append((name, int(fa), raw, name))
            else:
                targets = self._narrow(
                    self._discover(
                        r, elf_base, text_range, baddr, _addr_targets_of(function_names)
                    ),
                    function_names,
                    binary_path.name,
                )
            for label, file_addr, raw, r2_flag in targets:
                try:
                    provenance = self._decompile_one_native(r, used_cmd, raw)
                except Exception as e:  # noqa: BLE001
                    _l.debug("r2dec failed on %s@%#x: %s", r2_flag, raw, e)
                    provenance = None
                fd = self._make_function(
                    r2_flag,
                    file_addr,
                    str((provenance or {}).get("code") or ""),
                    label,
                    provenance,
                    r2_addr=raw,
                    baddr=baddr,
                    elf_base=elf_base,
                )
                if fd is None:
                    failed.append(label or _r2_bare_name(r2_flag))
                else:
                    decompiled[fd.name] = fd
                _dump()
        except Exception as e:  # noqa: BLE001
            _l.error("r2dec native run failed on %s: %s", binary_path, e)
            if not decompiled:
                failed = [t[0] or _r2_bare_name(t[3]) for t in targets] or ["all"]
        finally:
            if r is not None:
                with contextlib.suppress(Exception):
                    r.quit()

        result = self._make_result(
            binary_path, decompiled, failed, time.time() - start, "native", used_cmd, output_dir
        )
        self._write_artifacts(result, output_dir, binary_path)
        return result

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
        text_range = raw_common.elf_text_range(binary_path)

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
                )
                out_json = work_dir / "out.json"
                if out_json.is_file():
                    entries = json.loads(out_json.read_text() or "[]")
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
        addr_targets = _addr_targets_of(function_names)
        for entry in entries:
            raw = entry.get("addr")
            if raw is None:
                continue
            b = int(entry.get("baddr") or 0)
            file_addr = int(raw) - b + elf_base
            nm = entry.get("name") or ""
            if _r2_is_import(nm) or nm in _R2_ENTRY_NAMES:
                continue
            if _skip_r2_function(_r2_bare_name(nm), file_addr, text_range, addr_targets):
                continue
            by_addr[file_addr] = (nm, entry)
            discovered.append((nm, file_addr, int(raw)))
        discovered.sort(key=lambda t: t[1])
        targets = self._narrow(discovered, function_names, binary_path.name)

        decompiled: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        for label, file_addr, _raw, r2_flag in targets:
            _nm, entry = by_addr.get(file_addr, (r2_flag, {}))
            entry_baddr = _r2_int(entry.get("baddr"), 0) or 0
            fd = self._make_function(
                r2_flag,
                file_addr,
                str(entry.get("code") or ""),
                label,
                entry,
                r2_addr=_r2_int(entry.get("addr"), _raw),
                baddr=entry_baddr,
                elf_base=elf_base,
            )
            if fd is None:
                failed.append(label or _r2_bare_name(r2_flag))
            else:
                decompiled[fd.name] = fd
        if not entries and not decompiled:
            failed = failed or ["all"]

        result = self._make_result(
            binary_path,
            decompiled,
            failed,
            time.time() - start,
            "docker",
            "pdd",
            output_dir,
            timed_out=timed_out,
            error=error,
        )
        raw_common.dump_progress(progress_path, result)
        self._write_artifacts(result, output_dir, binary_path)
        return result

    @staticmethod
    def _r2_baddr(r: Any) -> int:
        """radare2's load base address (``baddr``) for the open binary."""
        try:
            info = r.cmdj("ij") or {}
            return int((info.get("bin") or {}).get("baddr") or 0)
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _probe_decompile_cmd(r: Any) -> str:
        """Pick the decompile command: the real r2dec ``pdd`` or built-in ``pdc``."""
        try:
            out = r.cmd("pdd @ entry0")
        except Exception:  # noqa: BLE001
            out = ""
        if out and "install the plugin" not in out and "Cannot find" not in out:
            return "pdd"
        return "pdc"

    @staticmethod
    def _decompile_one_native(r: Any, cmd: str, addr: int) -> dict[str, Any] | None:
        """Decompile one function and collect r2-native provenance."""
        code = ""
        line_mappings: list[dict[str, Any]] = []
        if cmd in {"pdd", "pdc"}:
            payload = _r2_cmdj(r, f"{cmd}j @ {addr}", None)
            parsed = _r2_json_lines(payload) if cmd == "pdd" else _r2_json_annotations(payload)
            if parsed is not None:
                code, line_mappings = parsed
        if not code:
            raw = r.cmd(f"{cmd} @ {addr}")
            if raw:
                code = str(raw).strip()
        if not code or "install the plugin" in code:
            return None

        function_info = _r2_cmdj(r, f"afij @ {addr}", [])
        info = (
            function_info[0]
            if isinstance(function_info, list)
            and function_info
            and isinstance(function_info[0], dict)
            else {}
        )
        binary_info = _r2_cmdj(r, "ij", {})
        architecture = str((binary_info.get("bin") or {}).get("arch") or "").lower()
        is_thumb = architecture.startswith("arm") and (
            (_r2_int(info.get("bits"), 0) or 0) == 16 or bool(addr & 1)
        )
        return {
            "addr": addr,
            "size": _r2_int(info.get("size"), 0) or 0,
            "is_thumb": is_thumb,
            "code": code,
            "line_mappings": line_mappings,
            "variables": _r2_variable_records(r, addr, line_mappings),
        }


__all__ = [
    "DockerizedDecompiler",
    "RetDecDecompiler",
    "RekoDecompiler",
    "R2DecDecompiler",
    "elf_function_symbols",
    "split_c_functions",
]
