"""Export a blinded external eval kit from a results tree's frozen sample-set.

``export_kit`` resolves every manifest entry to a real binary + DWARF address
(STRICT by default — a manifest that does not fully resolve is a bug worth
stopping for), strips + anonymizes copies of the binaries, and lays out the
contributor-facing kit (README, ``functions.json``, ``results/`` template,
standalone ``package.py``) plus a single-top-level-folder zip.

Address contract: ``functions.json`` ships DWARF ``low_pc`` ints — the virtual
addresses encoded in the binary's own headers (ELF program-header vaddrs; PE
``ImageBase + RVA``) — exactly the space the rest of DecBench stores.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import random
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from decbench.evalkit import EvalKitError, kit_package, resolve, templates

_l = logging.getLogger(__name__)

KIT_FORMAT_VERSION = 1

# Verbatim in functions.json: the space contributors must report addresses in.
ADDRESS_SPACE_NOTE = (
    "Virtual addresses as encoded in the binary's own headers (ELF: program-header "
    "vaddrs at the preferred/link base; PE: ImageBase + RVA). Report addresses in "
    "this space."
)


@dataclass
class KitSummary:
    """What an export produced (for the CLI to print)."""

    kit_dir: Path
    zip_path: Path | None
    n_binaries: int
    n_functions: int
    skipped: list[str] = field(default_factory=list)


@dataclass
class _KitBinary:
    """One resolved manifest binary headed into the kit."""

    project: str
    opt: str
    stem: str  # manifest/checkpoint key (Path(file).stem)
    path: Path  # the real on-disk binary (unstripped)
    functions: dict[str, int]  # DWARF name -> low_pc
    anon: str = ""


def _anon_extension(file_name: str) -> str:
    """The anonymized name's extension, derived from the original filename."""
    if ".so" in file_name:
        return ".so"
    suffix = Path(file_name).suffix.lower()
    if suffix in (".dll", ".exe"):
        return suffix
    return ".elf"


def _format_name(path: Path) -> str:
    """Human-readable format tag (ELF64-x86-64 / ELF32-ARM / PE32-i386 / ...)."""
    from decbench.utils import binfmt

    info = binfmt.detect(path)
    if info is None:
        raise EvalKitError(f"cannot detect binary format of {path}")
    arch = {"x86": "i386", "arm": "ARM", "aarch64": "AArch64"}.get(info.arch, info.arch)
    if info.fmt == "elf":
        return f"ELF{info.bits}-{arch}"
    return f"PE32{'+' if info.bits == 64 else ''}-{arch}"


def _load_manifest_functions(manifest_path: Path) -> list[dict]:
    """The manifest's function entries, schema-checked via ``SubsetManifest``."""
    from decbench.scoring.subset import SubsetManifest

    if not manifest_path.is_file():
        raise EvalKitError(f"manifest not found: {manifest_path}")
    try:
        return SubsetManifest.from_json(manifest_path).functions
    except Exception as e:  # noqa: BLE001
        raise EvalKitError(f"cannot load manifest {manifest_path}: {e}") from e


def _resolve_manifest(
    tree: Path, entries: list[dict], allow_unresolved: bool
) -> tuple[list[_KitBinary], list[str]]:
    """Resolve manifest entries to binaries + DWARF addresses.

    Returns ``(kit_binaries, failure_notes)``. In strict mode the caller raises
    on any failure; with ``allow_unresolved`` the notes become ``skipped``.
    """
    failures: list[str] = []
    groups: dict[tuple[str, str, str], set[str]] = {}
    for entry in entries:
        missing = [k for k in ("project", "opt", "binary", "function") if not entry.get(k)]
        if missing:
            failures.append(f"manifest entry {entry!r}: missing keys {missing}")
            continue
        key = (entry["project"], entry["opt"], entry["binary"])
        groups.setdefault(key, set()).add(entry["function"])

    bins: list[_KitBinary] = []
    for (project, opt, stem), names in sorted(groups.items()):
        try:
            path = resolve.discover_binary(tree, opt, project, stem)
        except FileNotFoundError as e:
            failures.append(f"{project}/{opt}/{stem}: {e}")
            continue
        stems = resolve.source_stems(tree, opt, project)
        addr_by_name = resolve.name_to_addr(path, names=names, stems=stems or None)
        for fn in sorted(names - set(addr_by_name)):
            failures.append(
                f"{project}/{opt}/{stem}::{fn}: no DWARF address "
                f"(decl-file-filtered subprogram walk over {path.name})"
            )
        funcs = {fn: addr_by_name[fn] for fn in sorted(names & set(addr_by_name))}
        if funcs:
            bins.append(_KitBinary(project, opt, stem, path, funcs))
        elif allow_unresolved:
            _l.warning("%s/%s/%s: no resolvable functions; binary skipped", project, opt, stem)
    return bins, failures


def manifest_fingerprint(entries: list[dict]) -> str:
    """Stable sha256 over a manifest's ``(project, opt, binary, function)`` set.

    Stamped into the kit and carried through the packaged submission so ingest
    can tell that a tree's manifest was re-frozen after the kit went out — the
    drift that otherwise shows up only as functions silently dropped at ingest.
    Hashed from the manifest as READ, so a kit that legitimately ships a subset
    (``allow_unresolved``) still fingerprints the manifest it came from.
    """
    keys = sorted(
        "\x00".join(str(e.get(k, "")) for k in ("project", "opt", "binary", "function"))
        for e in entries
    )
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()


def _strip_into(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst`` and strip the COPY (never the original).

    ELF additionally drops ``.comment`` and the build-id note — both identify
    the original toolchain/build and serve no analysis purpose.
    """
    from decbench.utils import binfmt

    if shutil.which("strip") is None:
        raise EvalKitError("GNU `strip` not found on PATH; cannot anonymize binaries")
    info = binfmt.detect(src)
    if info is None:
        raise EvalKitError(f"cannot detect binary format of {src}")
    shutil.copy2(src, dst)
    cmd = ["strip", "--strip-all"]
    if info.fmt == "elf":
        cmd += ["-R", ".comment", "-R", ".note.gnu.build-id"]
    proc = subprocess.run([*cmd, str(dst)], capture_output=True, text=True)
    if proc.returncode != 0:
        raise EvalKitError(f"strip failed for {src.name}: {proc.stderr.strip() or proc.stdout}")
    # Ship non-executable: some kit binaries are real malware and the README
    # says never to run them — don't hand out a chmod +x that invites it.
    dst.chmod(0o644)


def _lief_sections(path: Path) -> dict[str, bytes]:
    """Section name -> content via LIEF (parses ELF and PE alike)."""
    import lief

    with contextlib.suppress(Exception):  # LIEF chatters on stderr otherwise
        lief.logging.disable()
    binary = lief.parse(str(path))
    if binary is None:
        raise EvalKitError(f"LIEF cannot parse {path}")
    # LIEF types section names as str | bytes; decode defensively.
    return {
        sec.name.decode() if isinstance(sec.name, bytes) else sec.name: bytes(sec.content)
        for sec in binary.sections
    }


def _pe_debug_leftovers(path: Path) -> list[str]:
    """Debug sections still present in a PE, by RESOLVED name.

    PE section headers are 8 bytes, so long names live in the COFF string table
    and the header holds a ``/<offset>`` reference — an unstripped PE therefore
    shows LIEF names like ``/29``, never ``.debug_info``. Resolving them is the
    only way to see leftover DWARF. Also flags a surviving COFF symbol table,
    which ``strip --strip-all`` always removes.
    """
    import lief

    with contextlib.suppress(Exception):
        lief.logging.disable()
    binary = lief.parse(str(path))
    if binary is None:
        raise EvalKitError(f"LIEF cannot parse {path}")
    leftovers: list[str] = []
    if getattr(binary.header, "numberof_symbols", 0):
        leftovers.append("COFF symbol table")
    raw = path.read_bytes()
    # The string table sits right after the symbol table; its first 4 bytes are
    # its own size. Without a symbol table pointer there is nothing to resolve.
    ptr = int(getattr(binary.header, "pointerto_symbol_table", 0) or 0)
    nsyms = int(getattr(binary.header, "numberof_symbols", 0) or 0)
    strtab_off = ptr + nsyms * 18 if ptr else 0
    for sec in binary.sections:
        name = sec.name.decode() if isinstance(sec.name, bytes) else sec.name
        if not name.startswith("/"):
            if name.startswith(".debug"):
                leftovers.append(name)
            continue
        if not strtab_off or not name[1:].isdigit():
            continue
        start = strtab_off + int(name[1:])
        end = raw.find(b"\x00", start)
        if 0 <= start < len(raw) and end > start:
            resolved = raw[start:end].decode("utf-8", "replace")
            if resolved.startswith(".debug"):
                leftovers.append(resolved)
    return leftovers


_SHF_EXECINSTR = 0x4


def _code_sections(path: Path) -> dict[str, bytes]:
    """Executable section name -> content.

    Not every corpus binary calls its code ``.text``: armlink-produced firmware
    (e.g. crazyflie's ``CMSIS_DAP.axf``) uses scatter-loading region names like
    ``ER_ROM1``. Select by the executable flag and fall back to ``.text`` for
    formats LIEF does not flag (PE).
    """
    import lief

    with contextlib.suppress(Exception):
        lief.logging.disable()
    binary = lief.parse(str(path))
    if binary is None:
        raise EvalKitError(f"LIEF cannot parse {path}")
    out: dict[str, bytes] = {}
    for sec in binary.sections:
        name = sec.name.decode() if isinstance(sec.name, bytes) else sec.name
        flags = getattr(sec, "flags", None)
        if isinstance(flags, int) and flags & _SHF_EXECINSTR:
            out[name] = bytes(sec.content)
    if not out:
        all_secs = _lief_sections(path)
        if ".text" in all_secs:
            out[".text"] = all_secs[".text"]
    return out


def _verify_strip(original: Path, stripped: Path) -> None:
    """Fail hard unless the strip kept the code intact and removed all DWARF.

    LIEF section content is the comparison basis on purpose: it parses ELF and
    PE alike, and pyelftools' ``has_dwarf_info()`` false-positives on
    ``.eh_frame``. PE needs the extra long-name resolution below, since its
    ``.debug_*`` sections are never spelled out in the section headers.
    """
    from decbench.utils import binfmt

    new_secs = _lief_sections(stripped)
    orig_code = _code_sections(original)
    new_code = _code_sections(stripped)
    if not orig_code or not new_code:
        raise EvalKitError(f"{original.name}: no executable section to verify after strip")
    if set(orig_code) != set(new_code):
        raise EvalKitError(
            f"{original.name}: executable sections changed during strip "
            f"({sorted(orig_code)} -> {sorted(new_code)}) — refusing to ship"
        )
    for name, data in orig_code.items():
        if new_code[name] != data:
            raise EvalKitError(f"{original.name}: {name} changed during strip — refusing to ship")
    info = binfmt.detect(stripped)
    if info is not None and info.fmt == "pe":
        leftover = sorted(set(_pe_debug_leftovers(stripped)))
    else:
        leftover = sorted(n for n in new_secs if n.startswith(".debug"))
    if leftover:
        raise EvalKitError(f"{original.name}: debug data survived strip: {leftover}")


def export_kit(
    tree: Path,
    output_dir: Path,
    dataset: str = "sample-set",
    manifest: Path | None = None,
    seed: int = 1337,
    make_zip: bool = True,
    allow_unresolved: bool = False,
) -> KitSummary:
    """Build an external eval kit at ``output_dir`` (the kit dir itself).

    STRICT by default: every manifest entry must resolve to a binary on disk
    and a DWARF address, else an :class:`EvalKitError` lists every failure.
    ``allow_unresolved=True`` downgrades those to warnings + ``skipped`` notes.
    """
    tree = Path(tree)
    kit_dir = Path(output_dir)
    if dataset != "sample-set":
        raise EvalKitError("only sample-set is supported for now")
    if not tree.is_dir():
        raise EvalKitError(f"results tree not found: {tree}")

    manifest_path = Path(manifest) if manifest is not None else tree / "sample_set_manifest.json"
    entries = _load_manifest_functions(manifest_path)
    if not entries:
        raise EvalKitError(f"manifest {manifest_path} lists no functions")

    bins, failures = _resolve_manifest(tree, entries, allow_unresolved)
    skipped: list[str] = []
    if failures:
        if not allow_unresolved:
            raise EvalKitError(
                f"{len(failures)} manifest entr{'y' if len(failures) == 1 else 'ies'} "
                "did not resolve (use allow_unresolved to skip):\n" + "\n".join(failures)
            )
        for note in failures:
            _l.warning("skipping unresolved: %s", note)
        skipped.extend(failures)
    if not bins:
        raise EvalKitError("nothing to export: no manifest entry resolved to a binary+address")

    # Anonymous identity assignment: deterministic for a given (manifest, seed).
    # Byte-identical duplicates (e.g. crazyflie's cf2.elf/firmware.elf) stay
    # SEPARATE anon binaries on purpose — each keeps its own per-binary identity
    # in the tree, so merging them would corrupt the de-anonymized mapping.
    bins.sort(key=lambda b: (b.project, b.opt, b.path.name))
    random.Random(seed).shuffle(bins)
    for i, b in enumerate(bins):
        b.anon = f"bin_{i:03d}{_anon_extension(b.path.name)}"

    binaries_dir = kit_dir / "binaries"
    results_dir = kit_dir / "results"
    for stale in (binaries_dir, results_dir):  # stale kit content is worse than none
        if stale.exists():
            shutil.rmtree(stale)
    binaries_dir.mkdir(parents=True)
    results_dir.mkdir(parents=True)

    public: dict[str, list[str]] = {}
    private: dict[str, dict] = {}
    n_functions = 0
    with tempfile.TemporaryDirectory(prefix="decbench-evalkit-") as tmp:
        for b in sorted(bins, key=lambda x: x.anon):
            work = Path(tmp) / b.anon
            _strip_into(b.path, work)
            _verify_strip(b.path, work)
            shutil.move(str(work), binaries_dir / b.anon)
            addrs = sorted(set(b.functions.values()))
            if len(addrs) != len(b.functions):
                _l.warning(
                    "%s/%s/%s: %d function names collapse onto %d addresses",
                    b.project,
                    b.opt,
                    b.stem,
                    len(b.functions),
                    len(addrs),
                )
            public[b.anon] = [f"0x{a:x}" for a in addrs]
            private[b.anon] = {
                "project": b.project,
                "opt": b.opt,
                "binary": b.stem,
                "file": b.path.name,
                "sha256_stripped": hashlib.sha256((binaries_dir / b.anon).read_bytes()).hexdigest(),
                "format": _format_name(b.path),
            }
            n_functions += len(addrs)

    functions_json = {
        "kit_format_version": KIT_FORMAT_VERSION,
        "dataset": dataset,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest_sha256": manifest_fingerprint(entries),
        "address_space": ADDRESS_SPACE_NOTE,
        "public": public,
        "private": private,
    }
    (kit_dir / "functions.json").write_text(json.dumps(functions_json, indent=2) + "\n")
    (kit_dir / "README.md").write_text(templates.kit_readme(dataset, len(bins), n_functions))
    # package.py is the kit_package module source VERBATIM — it must stay
    # standalone (stdlib-only, no decbench imports) so contributors can run it.
    (kit_dir / "package.py").write_text(Path(kit_package.__file__).read_text())
    (results_dir / "README.md").write_text(templates.results_readme())
    (results_dir / "results.example.json").write_text(templates.results_example(public))

    zip_path: Path | None = None
    if make_zip:
        zip_path = kit_dir.parent / f"{kit_dir.name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(kit_dir.rglob("*")):
                if f.is_file():
                    zf.write(f, arcname=f"{kit_dir.name}/{f.relative_to(kit_dir)}")

    _l.info(
        "exported kit: %d binaries, %d functions -> %s%s",
        len(bins),
        n_functions,
        kit_dir,
        f" (+ {zip_path})" if zip_path else "",
    )
    return KitSummary(
        kit_dir=kit_dir,
        zip_path=zip_path,
        n_binaries=len(bins),
        n_functions=n_functions,
        skipped=skipped,
    )
