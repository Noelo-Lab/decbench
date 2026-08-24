"""Manifold decompiler backend.

Manifold (https://github.com/changliu98/manifold) is a whole-binary decompiler that runs
CompCert's compilation pipeline in reverse: the binary is raised through Mach ->
Linear -> RTL -> Cminor -> Csharpminor -> Clight and printed as one C
translation unit. Unlike angr/Ghidra/IDA there is no per-function entry point --
one process call decompiles the whole binary and writes a single ``.c`` file.

This backend therefore:

* runs manifold once per binary (with a timeout),
* splits the emitted translation unit into per-function definitions with a
  brace/string-aware scanner, and
* recovers each function's address from the ``FUN_<hex>`` names manifold gives
  functions in a stripped binary, plus the exact ``main`` / address relation in
  manifold's Clight JSON sidecar (falling back to the ELF symbol table when the
  binary still carries symbols).

That single run happens over one of two paths, tried in this order:

* **native** -- a ``manifold`` executable resolved from ``MANIFOLD_BIN``, the
  decompilers config, or ``$PATH``;
* **Docker** -- the ``decbench/manifold:latest`` image built from
  ``docker/manifold.Dockerfile`` by ``decbench decompiler-build manifold``,
  which compiles manifold (Rust + a pinned Z3) from source so a host needs
  nothing installed but Docker.

Both paths write the same whole-program ``.c``, so everything downstream of the
run is shared. Native wins when both exist: it avoids the container round-trip
and lets a developer benchmark a working tree.

Addresses are reported in **ELF-file space**, matching the other raw backends:
manifold reads the ELF's own virtual addresses, so its addresses are already in
that space and need no rebasing.

Native line and variable evidence is deliberately left unset. The Clight JSON
sidecar carries IR variables, but manifold's address-keyed Clight nodes lose
their node identity when the final C AST is assembled, before later for-loop,
variable-coalescing, and goto-elision passes. The backend therefore consumes
only the sidecar's function name/address relation. Joining final C variable names
to the earlier IR by spelling would not be native provenance. ``type_match``
scores the declared types through DecBench's C parser and usage fallback
(arguments by ABI position + locals by name), exactly as it does for the
code-only LLM backends. The producer-side contract needed to unlock native
evidence is documented in ``docs/decompilers.md``.
"""

from __future__ import annotations

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

from decbench.decompilers.base import Decompiler
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.decompilers.spec import load_versions_config, version_settings
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.docker_task import docker_task_label_args

_l = logging.getLogger(__name__)

_FUN_NAME = re.compile(r"^FUN_([0-9a-fA-F]+)$")
_CLIGHT_ADDRESS = re.compile(r"^0x([0-9a-fA-F]+)$")
_CLIGHT_JSON_FLAG = "--dump-clight-json"

# manifold_raw.py -> raw -> decompilers -> decbench -> repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOCKER_DIR = _REPO_ROOT / "docker"

# Path inside the image holding the manifold revision it was built from.
_IMAGE_REV_FILE = "/opt/manifold.rev"

# Upstream manifold, and the revision the image builds. Both mirror the
# Dockerfile's ARG defaults and are overridable by the matching env vars.
_DEFAULT_REPO = "https://github.com/changliu98/manifold"
_DEFAULT_REF = "master"

_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _executable(path: Path) -> Path | None:
    """``path`` if it is a runnable file, else None."""
    return path if path.is_file() and os.access(path, os.X_OK) else None


def _manifold_bin(version: str | None = None) -> Path | None:
    """Resolve the manifold executable.

    ``MANIFOLD_BIN`` is an explicit override and wins outright -- a bad value is
    a misconfiguration to report, not a reason to silently run some other build.
    Otherwise take ``binary`` from the decompilers config (per-version first,
    then the tool's default section), then fall back to ``$PATH``::

        [manifold]
        binary = "/opt/manifold/target/release/manifold"
        [manifold.versions."0.1"]
        binary = "/opt/manifold-0.1/target/release/manifold"
    """
    env = os.environ.get("MANIFOLD_BIN")
    if env:
        return _executable(Path(env))
    settings = [version_settings("manifold", version)]
    default = load_versions_config().get("manifold")
    if isinstance(default, dict):
        settings.append(default)
    for source in settings:
        binary = source.get("binary")
        if binary:
            exe = _executable(Path(str(binary)))
            if exe is not None:
                return exe
    which = shutil.which("manifold")
    return Path(which) if which else None


def _run_env() -> dict[str, str]:
    """Child environment: manifold links libz3 dynamically, so carry the extra
    library path (``MANIFOLD_LD_LIBRARY_PATH``) into ``LD_LIBRARY_PATH``."""
    env = dict(os.environ)
    extra = os.environ.get("MANIFOLD_LD_LIBRARY_PATH")
    if extra:
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{extra}:{prev}" if prev else extra
    # Manifold's rayon pool defaults to every core; a parallel driver must cap it.
    threads = os.environ.get("MANIFOLD_THREADS")
    if threads:
        env["RAYON_NUM_THREADS"] = threads
    return env


def _docker_bin() -> str | None:
    return shutil.which("docker")


def _resolve_ref(repo: str, ref: str) -> str | None:
    """``ref`` resolved to a commit SHA against ``repo``, or None if it cannot be.

    This is what keeps a rebuild honest. Docker keys the ``RUN git clone`` layer
    on the command string, which does not change when the branch moves, so
    rebuilding against a bare ``master`` reuses the cached clone and silently
    ships the revision the image already had. Passing the resolved SHA as the
    build arg changes that layer's key exactly when upstream moved -- and leaves
    it cached, along with the expensive apt/rust/z3 layers, when it did not.
    """
    if _SHA.match(ref):
        return ref
    git = shutil.which("git")
    if not git:
        _l.warning(
            "manifold: git not found; cannot resolve %s, rebuild may reuse a stale clone", ref
        )
        return None
    try:
        proc = subprocess.run(
            [git, "ls-remote", repo, ref],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:  # noqa: BLE001
        _l.warning("manifold: could not reach %s to resolve %s: %s", repo, ref, e)
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        _l.warning("manifold: %s does not name a ref in %s", ref, repo)
        return None
    return proc.stdout.split()[0]


def _image_present(image: str) -> bool:
    """True iff ``docker image inspect <image>`` succeeds.

    Never builds: building manifold is a multi-minute side effect, so it stays
    an explicit ``decbench decompiler-build manifold``, as for the other
    container-backed backends.
    """
    docker = _docker_bin()
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


def _strip_comments_and_strings(text: str) -> str:
    """Blank out string/char literals and comments, preserving offsets.

    The function splitter scans for braces and parens; a ``'{'`` inside a string
    literal or a comment must not move the depth counter. Replacing those spans
    with spaces (same length) keeps every offset valid for slicing the original.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c in ("'", '"'):
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _declarator_name(decl: str) -> str | None:
    """The function name in a declarator like ``long FUN_401136(void *p0, int n)``.

    The parameter list is the paren group that closes at the end of ``decl``;
    the name is the identifier immediately before it.
    """
    decl = decl.strip()
    if not decl.endswith(")"):
        return None
    depth = 0
    open_i = None
    for i in range(len(decl) - 1, -1, -1):
        c = decl[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                open_i = i
                break
    if open_i is None:
        return None
    m = re.search(r"([A-Za-z_]\w*)\s*$", decl[:open_i])
    return m.group(1) if m else None


_IDENT = re.compile(r"[A-Za-z_]\w*")


class _Entity:
    """One top-level item of a manifold translation unit."""

    __slots__ = ("text", "defines", "refs", "is_function", "always")

    def __init__(self, text: str, defines: set[str], refs: set[str], is_function: bool):
        self.text = text
        self.defines = defines
        self.refs = refs
        self.is_function = is_function
        self.always = text.lstrip().startswith("#")


def parse_translation_unit(text: str) -> list[_Entity]:
    """Split a manifold translation unit into its top-level entities, in order.

    Walks top-level brace groups with a comment/string-aware scanner: the text
    since the last top-level ``;``/``}`` is the declarator, and a braced group
    whose declarator ends in a parameter list is a function definition (struct /
    union / enum definitions and prototypes end at a ``;`` instead).
    Preprocessor lines are their own entities.
    """
    scan = _strip_comments_and_strings(text)
    entities: list[_Entity] = []
    depth = 0
    decl_start = 0
    body_start = -1
    i, n = 0, len(scan)

    def emit(start: int, end: int, is_function: bool) -> None:
        chunk = text[start:end].strip()
        if not chunk:
            return
        idents = set(_IDENT.findall(_strip_comments_and_strings(chunk)))
        name = _declarator_name(text[start:body_start]) if is_function else None
        defines = {name} if name else _declared_names(chunk)
        entities.append(_Entity(chunk, defines, idents - defines, is_function))

    while i < n:
        c = scan[i]
        if depth == 0 and c == "#" and (i == 0 or scan[i - 1] == "\n"):
            j = scan.find("\n", i)
            j = n if j == -1 else j
            emit(decl_start, i, False)
            entities.append(_Entity(text[i:j].strip(), set(), set(), False))
            decl_start = j
            i = j
            continue
        if c == "{":
            if depth == 0:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                # A struct/union/enum definition continues to its ``;``.
                j = i + 1
                while j < n and scan[j] in " \t\r\n":
                    j += 1
                end = j + 1 if j < n and scan[j] == ";" else i + 1
                emit(decl_start, end, _declarator_name(text[decl_start:body_start]) is not None)
                decl_start = end
                body_start = -1
                i = end
                continue
        elif c == ";" and depth == 0:
            emit(decl_start, i + 1, False)
            decl_start = i + 1
        i += 1
    return entities


def _declared_names(chunk: str) -> set[str]:
    """Names a non-function top-level declaration introduces.

    Covers manifold's preamble forms: ``struct struct_1 { … };`` (the tag),
    ``long L_1f27b;`` / ``char L_2b031 = -1;`` / ``int L_205e0[1];`` (the
    variable), and ``extern unsigned char __TMC_END__;``.
    """
    body = _strip_comments_and_strings(chunk)
    m = re.match(r"\s*(?:typedef\s+)?(?:struct|union|enum)\s+([A-Za-z_]\w*)", body)
    if m:
        return {m.group(1)}
    head = re.split(r"[=;]", body, maxsplit=1)[0]
    head = re.sub(r"\[[^\]]*\]", "", head)
    m = re.search(r"([A-Za-z_]\w*)\s*$", head.strip())
    return {m.group(1)} if m else set()


def _with_preamble(func: _Entity, entities: list[_Entity]) -> str:
    """The function definition preceded by the file-scope items it references.

    Manifold prints one translation unit, but DecBench stores and recompiles one
    function at a time, so each function's stored code must carry the struct
    definitions and globals its body mentions -- transitively, since a struct's
    fields can name other structs. This mirrors the other backends' artifacts
    (angr's per-function code likewise repeats the typedefs and ``extern``
    globals the body uses).
    """
    by_name: dict[str, _Entity] = {}
    for e in entities:
        if e.is_function or e.always:
            continue
        for nm in e.defines:
            by_name.setdefault(nm, e)

    needed: set[int] = set()
    worklist = list(func.refs)
    seen: set[str] = set()
    while worklist:
        nm = worklist.pop()
        if nm in seen:
            continue
        seen.add(nm)
        ent = by_name.get(nm)
        if ent is None or id(ent) in needed:
            continue
        needed.add(id(ent))
        worklist.extend(ent.refs - seen)

    parts = [e.text for e in entities if e.always or id(e) in needed]
    parts.append(func.text)
    return "\n\n".join(parts)


def split_functions(text: str) -> list[tuple[str, str]]:
    """``(name, code)`` per function, each carrying the preamble it references."""
    entities = parse_translation_unit(text)
    out: list[tuple[str, str]] = []
    for e in entities:
        if not e.is_function:
            continue
        name = next(iter(e.defines), None)
        if name:
            out.append((name, _with_preamble(e, entities)))
    return out


def _symbol_addresses(binary_path: Path) -> dict[str, int]:
    """``name -> st_value`` for STT_FUNC symbols (unstripped binaries only)."""
    out: dict[str, int] = {}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue
                    if not sym.name or not sym["st_value"]:
                        continue
                    out.setdefault(sym.name, int(sym["st_value"]))
    except Exception as e:  # noqa: BLE001
        _l.debug("manifold: no symbol table for %s: %s", binary_path, e)
    return out


def _needs_clight_function_addresses(binary_path: Path) -> bool:
    """Whether manifold can recover a stripped literal ``main`` on this input.

    Upstream's current recovery recognizes the x86-64 ELF startup convention.
    Requiring the corresponding dynamic symbol keeps the relatively expensive
    Clight export off ARM firmware, PE files, shared libraries, and older/static
    startup shapes where it cannot supply the missing relation.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64" or not elf["e_entry"]:
                return False
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                if any(
                    sym.name.split("@", 1)[0] == "__libc_start_main" for sym in sec.iter_symbols()
                ):
                    return True
    except Exception as e:  # noqa: BLE001
        _l.debug("manifold: cannot inspect startup shape for %s: %s", binary_path, e)
    return False


def _clight_function_addresses(
    sidecar_path: Path,
    text_range: tuple[int, int] | None,
) -> dict[str, int]:
    """Read manifold's exact final-function address for literal ``main``.

    The relation recovers names such as literal ``main``, which otherwise lose
    the address encoded by a ``FUN_<hex>`` spelling. Everything else in the
    Clight export, including its pre-final-AST variables and other names, is
    ignored. The record is accepted only when its schema is exact, ``main`` is
    unique, and its address lies inside the binary's ``.text`` section.
    """
    if text_range is None or not sidecar_path.is_file():
        return {}
    try:
        document = json.loads(sidecar_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        _l.debug("manifold: unreadable Clight sidecar %s: %s", sidecar_path, e)
        return {}
    if not isinstance(document, dict) or document.get("compcert_clight") is not True:
        return {}
    rows = document.get("functions")
    if not isinstance(rows, list):
        return {}

    addresses: dict[str, int] = {}
    ambiguous: set[str] = set()
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        encoded = row.get("address")
        if name != "main":
            continue
        if name in seen:
            ambiguous.add(name)
            addresses.pop(name, None)
            continue
        seen.add(name)
        if not isinstance(encoded, str):
            continue
        match = _CLIGHT_ADDRESS.fullmatch(encoded)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if not common.in_text(address, text_range):
            continue
        addresses[name] = address
    for name in ambiguous:
        addresses.pop(name, None)
    return addresses


@register_decompiler("manifold")
class ManifoldDecompiler(Decompiler):
    """Manifold driven as a one-shot whole-binary run, natively or in Docker."""

    name = "manifold"
    display_name = "Manifold"

    #: Docker image built from :attr:`dockerfile`, used when no native manifold
    #: executable resolves. ``MANIFOLD_IMAGE`` overrides the tag.
    image = "decbench/manifold:latest"
    #: Dockerfile basename under ``docker/`` that builds :attr:`image`.
    dockerfile = "manifold.Dockerfile"

    #: Memo for :meth:`get_version`. Probing the Docker path costs a container
    #: spawn, and results ask for the version once per binary.
    _version_probed: bool = False
    _version_value: str | None = None

    @property
    def _image(self) -> str:
        return os.environ.get("MANIFOLD_IMAGE") or self.image

    def _select_path(self) -> tuple[str, Path | None]:
        """``("native", exe)``, ``("docker", None)``, or ``("none", None)``.

        Native first: it skips the container round-trip and lets a developer
        benchmark a working tree without rebuilding an image.
        """
        exe = _manifold_bin(self.requested_version)
        if exe is not None:
            return "native", exe
        if _image_present(self._image):
            return "docker", None
        return "none", None

    def is_available(self) -> bool:
        return self._select_path()[0] != "none"

    @classmethod
    def build_image(cls, no_cache: bool = False) -> int:
        """Build the manifold image; returns the ``docker build`` exit code.

        Runs ``docker build -f docker/manifold.Dockerfile -t <image> docker/``,
        the same shape as the container-backed backends, so ``decbench
        decompiler-build manifold`` picks this up through its ``build_image``
        hook. The build clones and compiles manifold from source, so it takes
        several minutes.

        ``MANIFOLD_REPO`` / ``MANIFOLD_REF`` select what is built. The ref is
        resolved to a SHA first, so re-running this after manifold gains commits
        actually rebuilds instead of reusing the cached clone -- see
        :func:`_resolve_ref`.
        """
        docker = _docker_bin()
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        dockerfile_path = _DOCKER_DIR / cls.dockerfile
        if not dockerfile_path.is_file():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")
        image = os.environ.get("MANIFOLD_IMAGE") or cls.image
        repo = os.environ.get("MANIFOLD_REPO") or _DEFAULT_REPO
        ref = os.environ.get("MANIFOLD_REF") or _DEFAULT_REF
        resolved = _resolve_ref(repo, ref)
        if resolved is None:
            # Better a slow honest build than a fast stale one.
            _l.warning("manifold: building %s with --no-cache (could not resolve %s)", image, ref)
            no_cache = True
        else:
            _l.info("manifold: %s resolves to %s", ref, resolved)
        cmd = [docker, "build", "-f", str(dockerfile_path), "-t", image]
        cmd += ["--build-arg", f"MANIFOLD_REPO={repo}"]
        cmd += ["--build-arg", f"MANIFOLD_REF={resolved or ref}"]
        if no_cache:
            cmd.append("--no-cache")
        cmd.append(str(_DOCKER_DIR))
        _l.info("Building %s: %s", image, " ".join(cmd))
        return subprocess.run(cmd).returncode

    def get_version(self) -> str | None:
        if not self._version_probed:
            self._version_value = self._probe_version()
            self._version_probed = True
        return self._version_value

    def _probe_version(self) -> str | None:
        env = os.environ.get("MANIFOLD_VERSION")
        if env:
            return env
        mode, exe = self._select_path()
        if mode == "docker":
            return self._docker_version()
        if exe is None:
            return None
        # No --version flag; identify the build by the revision it was built from.
        repo = exe.resolve().parents[2]
        try:
            rev = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if rev.returncode == 0 and rev.stdout.strip():
                return f"git-{rev.stdout.strip()}"
        except Exception:  # noqa: BLE001
            pass
        return self.requested_version or "unknown"

    def _docker_version(self) -> str | None:
        """The revision baked into the image, as the same ``git-<rev>`` string a
        native run reports. Falls back to the image tag if the file is absent."""
        docker = _docker_bin()
        image = self._image
        if docker:
            try:
                proc = subprocess.run(
                    [
                        docker,
                        "run",
                        "--rm",
                        *docker_task_label_args(),
                        "--entrypoint",
                        "cat",
                        image,
                        _IMAGE_REV_FILE,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return f"git-{proc.stdout.strip()}"
            except Exception as e:  # noqa: BLE001
                _l.debug("manifold: could not read %s from %s: %s", _IMAGE_REV_FILE, image, e)
        return image.rsplit(":", 1)[-1] if ":" in image else "unknown"

    def _run_docker(
        self,
        binary_path: Path,
        work_dir: Path,
        out_name: str,
        timeout_s: float,
    ) -> subprocess.CompletedProcess[str]:
        """Run manifold in its image: binary read-only at ``/in``, ``work_dir``
        read-write at ``/work``, output written to ``/work/<out_name>``.

        Same mount layout the retdec/reko/r2dec images use. It is spelled out
        here rather than reused from ``dockerized.py`` because that module
        imports this package, so the reverse import would be a cycle.
        """
        docker = _docker_bin()
        if not docker:
            raise RuntimeError("docker binary not found on PATH")
        cmd = [
            docker,
            "run",
            "--rm",
            *docker_task_label_args(),
            "-v",
            f"{binary_path.resolve()}:/in/{binary_path.name}:ro",
            "-v",
            f"{work_dir.resolve()}:/work",
        ]
        # Cap the container's rayon pool exactly as MANIFOLD_THREADS caps a
        # native run, so N binaries in parallel do not each grab every core.
        threads = os.environ.get("MANIFOLD_THREADS")
        if threads:
            cmd += ["-e", f"RAYON_NUM_THREADS={threads}"]
        cmd += [self._image, f"/in/{binary_path.name}", f"/work/{out_name}"]
        if _needs_clight_function_addresses(binary_path):
            cmd.append(_CLIGHT_JSON_FLAG)
        _l.debug("manifold docker run: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)

    def discover_functions(self, binary_path: Path) -> list[tuple[str, int]]:
        result = self.decompile_binary(binary_path)
        return [(fd.name, fd.address) for fd in result.functions.values()]

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile a whole binary in one manifold invocation.

        ``function_names`` carries the DWARF target *addresses* (the same
        contract as the other raw backends, see ``common.narrow_to_source``);
        manifold has no per-function entry point, so the narrowing is applied to
        the emitted functions rather than to the work.
        """
        mode, exe = self._select_path()
        if mode == "none":
            raise RuntimeError(
                "Decompiler 'manifold' is not available (set MANIFOLD_BIN to a "
                f"manifold executable, or run `decbench decompiler-build {self.name}` "
                f"to build the {self._image} image)"
            )

        start_time = time.time()
        elf_base = common.elf_min_vaddr(binary_path)
        text_range = common.elf_text_range(binary_path)
        timeout_s = self.config.binary_timeout_seconds

        def _meta(failed: list[str], extra: dict[str, Any]) -> DecompilerMetadata:
            # Stop the clock before probing the version: on the Docker path that
            # probe is a container spawn, which is not decompilation time.
            elapsed = time.time() - start_time
            run_via: dict[str, Any] = {"run_via": mode}
            if mode == "docker":
                run_via["image"] = self._image
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=elapsed,
                timeout_occurred=bool(extra.get("timeout")),
                failed_functions=failed,
                extra={"backend": "manifold", "via": "raw", **run_via, **extra},
            )

        def _error(msg: str, timed_out: bool = False) -> DecompilationResult:
            _l.error("manifold failed on %s: %s", binary_path, msg)
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=_meta(["all"], {"error": msg, "timeout": timed_out}),
                output_dir=output_dir,
            )

        with tempfile.TemporaryDirectory(prefix="manifold-dec-") as tmp:
            # The container writes into this same directory (bind-mounted at
            # /work), so both paths read the result back from one place.
            out_c = Path(tmp) / f"{binary_path.stem}.c"
            needs_clight_addresses = _needs_clight_function_addresses(binary_path)
            try:
                if mode == "docker":
                    proc = self._run_docker(binary_path, Path(tmp), out_c.name, timeout_s)
                else:
                    cmd = [str(exe), str(binary_path), str(out_c)]
                    if needs_clight_addresses:
                        cmd.append(_CLIGHT_JSON_FLAG)
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout_s,
                        env=_run_env(),
                    )
            except subprocess.TimeoutExpired:
                return _error(f"timeout after {timeout_s}s", timed_out=True)
            except Exception as e:  # noqa: BLE001
                return _error(f"spawn failed: {e}")

            if not out_c.is_file():
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
                return _error(f"no output (exit {proc.returncode}): {' | '.join(tail)}")
            text = out_c.read_text(errors="replace")
            clight_addresses = (
                _clight_function_addresses(out_c.with_suffix(".clight.json"), text_range)
                if needs_clight_addresses
                else {}
            )

        decompiled_functions: dict[str, FunctionDecompilation] = {}
        unaddressed: list[str] = []
        symbols: dict[str, int] | None = None

        for name, code in split_functions(text):
            m = _FUN_NAME.match(name)
            if m:
                file_addr = int(m.group(1), 16)
            else:
                addr = clight_addresses.get(name)
                if addr is None:
                    # Symbol-named function: the binary was not stripped.
                    if symbols is None:
                        symbols = _symbol_addresses(binary_path)
                    addr = symbols.get(name)
                    if addr is None:
                        unaddressed.append(name)
                        continue
                file_addr = addr
            if common.should_skip_function(name, file_addr, text_range):
                continue
            decompiled_functions[name] = FunctionDecompilation(
                name=name,
                address=file_addr,
                decompiled_code=code,
                line_count=len(code.splitlines()),
                metadata=common.extract_metrics(code),
            )

        kept = common.narrow_to_source(
            [(n, fd.address) for n, fd in decompiled_functions.items()],
            function_names,
            backend="manifold",
            binary_name=binary_path.name,
        )
        keep_names = {n for n, _ in kept}
        decompiled_functions = {n: fd for n, fd in decompiled_functions.items() if n in keep_names}

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=_meta(
                unaddressed,
                {
                    "elf_base": elf_base,
                    "translation_unit_lines": len(text.splitlines()),
                    "clight_function_addresses": len(clight_addresses),
                },
            ),
            functions=decompiled_functions,
            combined_source=text,
            output_dir=output_dir,
        )

        common.dump_progress(progress_path, result)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")

        return result
