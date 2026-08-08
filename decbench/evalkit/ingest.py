"""Ingest a packaged external eval-kit submission into a results tree.

``ingest_submission`` turns a contributor's ``results.zip`` (produced by the
kit's ``package.py`` — see :mod:`decbench.evalkit.kit_package`) into a new
**sample-set-only** decompiler column:

* per-binary ``.c`` files are split into per-function snippets and each
  submitted address is relabeled to its DWARF name (the same tolerance rules
  the run driver's ``_relabel_to_dwarf`` uses, via :class:`resolve.AddrLookup`);
* artifacts land in ``<tree>/<opt>/<project>/decompiled/<dec_id>_<stem>.{c,toml}``
  and the per-project ``checkpoints/<project>.pkl`` gains the decompiler
  additively (``DecompilerMetadata.extra["slice_scoped"] = True`` so the
  aggregation never stamps unattempted functions as failures);
* optionally the three metrics are evaluated inline through the same
  :func:`decbench.pipeline.evaluate.evaluate_decompilation` path the run
  driver uses, with source CFGs from the tree's ``.i`` files.

All evaluation imports are lazy: ``evaluate=False`` never touches pyjoern.

Drop/count semantics: a submitted function whose address is not one of the
frozen manifest's addresses for its (project, opt, binary) slice is dropped
with a warning and counted in ``n_dropped_extra`` (an unparseable address is
counted there too — it cannot be attributed to any manifest function).
Manifest functions absent from the submission become ``failed_functions``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import pickle
import re
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from decbench.evalkit import EvalKitError, resolve
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.langs import preprocessed_by_stem

if TYPE_CHECKING:
    from decbench.models.metrics import MetricResult

_l = logging.getLogger(__name__)

KIT_FORMAT_VERSION = 1

_DEC_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")

_REEVAL_DEFAULTS = (
    "angr",
    "ghidra",
    "ida",
    "binja",
    "kuna",
    "r2dec",
    "dewolf",
    "codex",
    "claude-code",
)

# The LLM backends' byte_match rides on inline checkpoint values, so the
# byte_match refresh command must not name them.
_LLM_BASENAMES = ("codex", "claude-code", "kimi-code")


@dataclass
class IngestSummary:
    """What an ingest did (for the CLI to print)."""

    dec_id: str
    n_binaries: int
    n_functions: int
    n_relabeled: int
    n_dropped_extra: int
    n_failed: int
    warnings: list[str] = field(default_factory=list)
    next_steps: str = ""


@dataclass
class _Entry:
    """One submitted binary, fully resolved and ready to merge."""

    project: str
    opt: str
    stem: str
    binary: Path
    result: DecompilationResult
    addrs: set[int]


@dataclass
class _Counters:
    relabeled: int = 0
    dropped_extra: int = 0


def _warn(warnings: list[str], msg: str) -> None:
    """Record a warning both in the summary list and on the module logger."""
    warnings.append(msg)
    _l.warning("%s", msg)


def _open_submission(submission: Path, stack: contextlib.ExitStack) -> tuple[dict, Path]:
    """Load the packaged ``results.json`` and the directory holding its ``.c`` files.

    Accepts the packaged ``results.zip``, an unpacked directory containing the
    packaged ``results.json``, or a direct path to that ``results.json``.
    """
    submission = Path(submission)
    if not submission.exists():
        raise EvalKitError(f"submission not found: {submission}")

    if submission.is_file() and submission.suffix.lower() == ".zip":
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="decbench-ingest-")))
        try:
            with zipfile.ZipFile(submission) as zf:
                for name in zf.namelist():
                    if name.startswith(("/", "..")) or ".." in Path(name).parts:
                        raise EvalKitError(f"unsafe path in {submission.name}: {name!r}")
                zf.extractall(tmp)
        except zipfile.BadZipFile as e:
            raise EvalKitError(f"cannot read zip {submission}: {e}") from e
        root = tmp
    elif submission.is_dir():
        root = submission
    elif submission.name == "results.json":
        root = submission.parent
    else:
        raise EvalKitError(
            f"submission must be a packaged results.zip, a directory containing the "
            f"packaged results.json, or that results.json itself (got {submission})"
        )

    results_path = root / "results.json"
    if not results_path.is_file():
        nested = [d / "results.json" for d in sorted(root.iterdir()) if d.is_dir()]
        hits = [p for p in nested if p.is_file()]
        if len(hits) == 1:
            results_path = hits[0]
            root = results_path.parent
        else:
            raise EvalKitError(f"no results.json found in {submission}")
    try:
        payload = json.loads(results_path.read_text())
    except ValueError as e:
        raise EvalKitError(f"cannot parse {results_path}: {e}") from e
    if not isinstance(payload, dict):
        raise EvalKitError(f"{results_path} is not a JSON object")
    return payload, root


def _require_packaged(payload: dict) -> dict[str, dict]:
    """The ``results`` mapping of a PACKAGED submission, or a "run package.py" error."""
    results = payload.get("results")
    if not isinstance(results, dict) or not results:
        raise EvalKitError('results.json has no "results" entries — nothing to ingest')
    raw = "kit_format_version" not in payload or any(
        not isinstance(e, dict) or not isinstance(e.get("binary"), dict) for e in results.values()
    )
    if raw:
        raise EvalKitError(
            "this looks like a RAW (un-packaged) results.json — run `python3 package.py` "
            "inside the kit and submit the results.zip it produces"
        )
    fmt = payload.get("kit_format_version")
    if fmt != KIT_FORMAT_VERSION:
        raise EvalKitError(
            f"unsupported kit_format_version {fmt!r} (this decbench understands "
            f"{KIT_FORMAT_VERSION})"
        )
    return results


def _check_manifest_drift(tree: Path, payload: dict, warnings: list[str]) -> None:
    """Warn when the tree's manifest was re-frozen after the kit was exported.

    A drifted manifest is not fatal — the picks a kit and a tree still share
    ingest normally — but the difference surfaces downstream only as functions
    quietly dropped ("not a manifest function") or counted as failures, which
    reads like a bad submission rather than a stale kit.
    """
    from decbench.evalkit.export import manifest_fingerprint
    from decbench.scoring.subset import SubsetManifest

    stamped = payload.get("manifest_sha256")
    if not isinstance(stamped, str) or not stamped:
        _warn(
            warnings,
            "submission carries no manifest fingerprint (kit predates it) — cannot "
            "verify it was built from this tree's current sample-set manifest",
        )
        return
    path = tree / "sample_set_manifest.json"
    try:
        current = manifest_fingerprint(SubsetManifest.from_json(path).functions)
    except Exception as e:  # noqa: BLE001
        _warn(warnings, f"cannot fingerprint {path} to check kit drift: {e}")
        return
    if current != stamped:
        _warn(
            warnings,
            f"MANIFEST DRIFT: this kit was exported from a different sample-set "
            f"manifest than {path} holds now (kit {stamped[:12]}, tree "
            f"{current[:12]}). Functions the two do not share will be dropped or "
            f"counted as failures. Re-export the kit and ask for a resubmission, "
            f"or ingest against the manifest the kit was built from.",
        )


def _parse_addr(value: object) -> int | None:
    """An address as int; accepts hex strings ("0x1234"/"1234") and bare ints."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            addr = int(value, 16)
        except ValueError:
            return None
        return addr if addr >= 0 else None
    return None


def _extract_definition(text: str, name: str) -> str | None:
    """Locate ``name(...) { ... }`` directly when ``split_c_functions`` missed it.

    The splitter only recognizes definitions whose ``name(...) {`` fits on one
    line; this fallback tolerates multi-line signatures. Like the splitter it
    is a heuristic (no real lexer): parens/braces inside string literals can
    confuse it, in which case the function is simply treated as missing.
    """
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        n = len(text)
        depth = 0
        j = m.end() - 1
        while j < n:
            ch = text[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            continue
        k = j + 1
        while k < n and text[k] in " \t\r\n":
            k += 1
        if k >= n or text[k] != "{":
            continue
        depth = 0
        e = k
        while e < n:
            ch = text[e]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            e += 1
        if e >= n:
            continue
        start = text.rfind("\n", 0, m.start()) + 1
        lines = text[:start].splitlines(keepends=True)
        while lines:
            prev = lines[-1].strip()
            if not prev or prev.endswith((";", "}", "{", "*/")) or prev.startswith(("#", "//")):
                break
            start -= len(lines.pop())
        return text[start : e + 1].rstrip() + "\n"
    return None


def _build_entry(
    tree: Path,
    manifest: set[tuple[str, str, str, str]],
    c_dir: Path,
    c_name: str,
    entry: dict,
    dec_id: str,
    version: str | None,
    dataset: str,
    counters: _Counters,
    warnings: list[str],
) -> _Entry | None:
    """Resolve one packaged results entry into an :class:`_Entry` (or skip it)."""
    from decbench.decompilers.dockerized import split_c_functions
    from decbench.decompilers.raw.common import extract_metrics
    from decbench.models.project import OptimizationLevel

    ident = entry.get("binary")
    if not isinstance(ident, dict):
        raise EvalKitError(f"results.json[{c_name!r}]: packaged 'binary' identity missing")
    project = ident.get("project")
    opt = ident.get("opt")
    stem = ident.get("binary")
    file_name = ident.get("file")
    # Per-name checks rather than all(...) so mypy narrows each to str.
    if (
        not isinstance(project, str)
        or not project
        or not isinstance(opt, str)
        or not opt
        or not isinstance(stem, str)
        or not stem
    ):
        raise EvalKitError(f"results.json[{c_name!r}]: incomplete binary identity {ident!r}")
    if not isinstance(file_name, str) or not file_name:
        file_name = None
    try:
        OptimizationLevel(opt)
    except ValueError as e:
        raise EvalKitError(f"results.json[{c_name!r}]: unknown opt level {opt!r}") from e
    where = f"{project}/{opt}/{stem}"

    funcs = entry.get("functions")
    if not isinstance(funcs, dict) or not funcs:
        raise EvalKitError(f"results.json[{c_name!r}]: 'functions' must be a non-empty object")

    c_path = c_dir / c_name
    if not c_path.is_file():
        raise EvalKitError(f"submission is missing the listed file {c_name}")
    c_text = c_path.read_text(errors="replace")

    try:
        binary = resolve.discover_binary(tree, opt, project, file_name or stem)
    except FileNotFoundError:
        if file_name and file_name != stem:
            try:
                binary = resolve.discover_binary(tree, opt, project, stem)
            except FileNotFoundError as e:
                raise EvalKitError(f"{where}: {e}") from e
        else:
            raise EvalKitError(f"{where}: binary not found in tree {tree}") from None

    allowed = {fn for (p, o, b, fn) in manifest if p == project and o == opt and b == stem}
    if not allowed:
        _warn(
            warnings,
            f"{where}: not a sample-set binary (no manifest functions) — "
            f"entry skipped, {len(funcs)} function(s) dropped",
        )
        counters.dropped_extra += len(funcs)
        return None

    stems = resolve.source_stems(tree, opt, project)
    lookup = resolve.AddrLookup.for_binary(binary, stems=stems or None)
    name2addr = resolve.name_to_addr(binary, names=allowed, stems=stems or None)
    snippets = split_c_functions(c_text)

    kept: dict[str, FunctionDecompilation] = {}
    for sub_name in sorted(funcs):
        addr = _parse_addr(funcs[sub_name])
        if addr is None:
            _warn(
                warnings,
                f"{where}: {sub_name} has unparseable address {funcs[sub_name]!r} — dropped",
            )
            counters.dropped_extra += 1
            continue
        dwarf_name = lookup.name_for(addr)
        if dwarf_name is None or dwarf_name not in allowed:
            _warn(
                warnings,
                f"{where}: {sub_name} @ 0x{addr:x} is not a manifest function of this "
                f"slice — dropped",
            )
            counters.dropped_extra += 1
            continue
        code = snippets.get(sub_name) or _extract_definition(c_text, sub_name)
        if not code:
            _warn(
                warnings,
                f"{where}: no definition of {sub_name} found in {c_name} — "
                f"{dwarf_name} counts as failed",
            )
            continue
        if dwarf_name != sub_name:
            code = re.sub(r"\b" + re.escape(sub_name) + r"\b", dwarf_name, code)
            counters.relabeled += 1
        low_pc = name2addr.get(dwarf_name, addr)
        prev = kept.get(dwarf_name)
        if prev is not None:
            _warn(
                warnings,
                f"{where}: {sub_name} and another submitted function both relabel to "
                f"{dwarf_name} — keeping the larger body",
            )
            if len(code) < len(prev.decompiled_code or ""):
                continue
        kept[dwarf_name] = FunctionDecompilation(
            name=dwarf_name,
            address=low_pc,
            decompiled_code=code,
            line_count=code.count("\n") + 1,
            metadata=extract_metrics(code),
        )

    failed = sorted(allowed - set(kept))
    result = DecompilationResult(
        binary_path=binary,
        binary_name=stem,
        decompiler=DecompilerMetadata(
            decompiler_name=dec_id,
            decompiler_version=version,
            failed_functions=failed,
            extra={"slice_scoped": True, "external_submission": True, "kit_dataset": dataset},
        ),
        functions=kept,
    )
    return _Entry(
        project=project,
        opt=opt,
        stem=stem,
        binary=binary,
        result=result,
        addrs={fd.address for fd in kept.values()},
    )


def _load_checkpoint(path: Path) -> dict:
    """Load (or initialize) a per-project checkpoint pickle."""
    if not path.exists():
        return {"decompile": {}, "evaluate": {}}
    import decbench.decompilers  # noqa: F401
    import decbench.metrics  # noqa: F401

    try:
        data = pickle.loads(path.read_bytes())
    except Exception as e:  # noqa: BLE001
        raise EvalKitError(f"unreadable checkpoint {path}: {e}") from e
    if not isinstance(data, dict):
        raise EvalKitError(f"checkpoint {path} has an unexpected shape")
    data.setdefault("decompile", {})
    data.setdefault("evaluate", {})
    return data


def _write_checkpoint(path: Path, data: dict) -> None:
    """Atomically pickle a checkpoint (tmp sibling + rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(pickle.dumps(data))
    tmp.replace(path)


def _purge_dec_slices(
    tree: Path,
    project: str,
    ckpt: dict,
    dec_id: str,
    keep: set[tuple[str, str, str]],
    warnings: list[str] | None,
) -> bool:
    """Drop one project's ``dec_id`` slices that are not in ``keep``.

    Mutates ``ckpt`` in place and deletes the matching artifacts (idempotent —
    ``unlink(missing_ok=True)``), so it is safe to re-apply to a freshly
    re-read checkpoint. ``warnings=None`` suppresses the notes on that replay.
    """
    dropped = False
    for kind in ("decompile", "evaluate"):
        for okey, bins in (ckpt.get(kind) or {}).items():
            optn = getattr(okey, "value", str(okey))
            for stem, decs in list((bins or {}).items()):
                if dec_id not in (decs or {}) or (project, optn, stem) in keep:
                    continue
                decs.pop(dec_id, None)
                dropped = True
                if kind == "decompile":
                    if warnings is not None:
                        _warn(
                            warnings,
                            f"force: dropped stale {dec_id} slice {project}/{optn}/{stem} "
                            f"(not present in this submission)",
                        )
                    art_dir = tree / optn / project / "decompiled"
                    for suffix in (".c", ".toml"):
                        (art_dir / f"{dec_id}_{stem}{suffix}").unlink(missing_ok=True)
    return dropped


def _purge_stale_slices(
    tree: Path,
    ckpts: dict[str, dict],
    dec_id: str,
    keep: set[tuple[str, str, str]],
    warnings: list[str],
) -> None:
    """Drop ``dec_id`` slices a re-ingest no longer covers (``force`` only).

    Without this, a corrected resubmission covering fewer binaries would leave
    the previous submission's slices behind and the published column would mix
    two submissions. Every project in the tree is swept, not just the ones this
    submission touches — a resubmission can drop a whole project. Projects the
    new submission DOES touch are re-purged at merge time against a freshly
    re-read checkpoint; the in-memory pass here is what produces the warnings.
    """
    for project, ckpt in ckpts.items():
        _purge_dec_slices(tree, project, ckpt, dec_id, keep, warnings)
    for pkl in sorted((tree / "checkpoints").glob("*.pkl")):
        if pkl.stem in ckpts:
            continue
        other = _load_checkpoint(pkl)
        if _purge_dec_slices(tree, pkl.stem, other, dec_id, keep, warnings):
            _write_checkpoint(pkl, other)


def _opt_key(section: dict, opt: str) -> Any:
    """The key to use for ``opt`` in a checkpoint section.

    Run-driver checkpoints key opts by :class:`OptimizationLevel`; tolerate
    plain-string keys in hand-built trees by reusing whichever form is present.
    """
    from decbench.models.project import OptimizationLevel

    enum_key = OptimizationLevel(opt)
    if enum_key in section:
        return enum_key
    if opt in section:
        return opt
    return enum_key


def _stems_for_addrs(binary: Path, addrs: set[int], stems: set[str]) -> set[str]:
    """The ``.i`` TU stems whose DWARF subprograms cover ``addrs``.

    Mirrors ``project_source_functions``' ``stem_out`` (scripts/run_benchmark.py)
    so Joern parses only the translation units that hold the target functions.
    Empty result means "unknown" — the caller falls back to every TU.
    """
    if not stems or not addrs:
        return set()
    from decbench.utils import binfmt

    try:
        dw = binfmt.dwarf_info(binary)
    except Exception:  # noqa: BLE001
        return set()
    if dw is None:
        return set()
    matched: set[str] = set()
    try:
        for cu in dw.iter_CUs():
            lp = dw.line_program_for_CU(cu)
            version = 4
            if lp is not None:
                version = lp.header.get("version", cu.header.get("version", 4))
            files: list[str | None] = [] if version >= 5 else [None]
            if lp is not None:
                for fe in lp["file_entry"]:
                    nm = fe.name
                    files.append(nm.decode() if isinstance(nm, bytes) else nm)
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                attrs = die.attributes
                if "DW_AT_low_pc" not in attrs:
                    continue
                if int(attrs["DW_AT_low_pc"].value) not in addrs:
                    continue
                fi = attrs.get("DW_AT_decl_file")
                if fi is None or not (0 <= fi.value < len(files)) or files[fi.value] is None:
                    continue
                base = os.path.basename(files[fi.value])  # type: ignore[arg-type]
                stem = base[:-2] if base.endswith(".c") else base
                if stem in stems:
                    matched.add(stem)
                    continue
                for s in stems:
                    if s.endswith("-" + stem) or s.endswith("_" + stem):
                        matched.add(s)
                        break
    except Exception:  # noqa: BLE001
        return set()
    return matched


def _evaluate_group(
    tree: Path,
    project: str,
    opt: str,
    entries: list[_Entry],
    metric_names: list[str],
    needs_source: bool,
    warnings: list[str],
) -> dict[str, dict[str, MetricResult]]:
    """Evaluate one (project, opt) group; returns ``{stem: {metric: MetricResult}}``.

    Reuses the run driver's evaluation path: source CFGs come from the tree's
    ``.i`` files (restricted to the TUs holding the target functions), matched
    TU-aware exactly like ``pipeline.evaluate.evaluate_project``.
    """
    from decbench.pipeline.evaluate import evaluate_decompilation
    from decbench.utils.cfg import (
        best_source_by_name,
        extract_cfgs_from_source,
        resolved_source_for_binary,
    )

    src_by_stem: dict[str, dict] = {}
    best: dict = {}
    if needs_source:
        compiled = tree / opt / project / "compiled"
        i_by_stem = preprocessed_by_stem(compiled)
        if not i_by_stem:
            _warn(
                warnings,
                f"{project}/{opt}: no preprocessed .i/.ii sources in {compiled} — "
                f"source-CFG metrics (GED) will not score",
            )
        else:
            needed: set[str] = set()
            for e in entries:
                got = _stems_for_addrs(e.binary, e.addrs, set(i_by_stem))
                if not got:
                    needed = set(i_by_stem)
                    break
                needed |= got
            for stem in sorted(needed):
                try:
                    src_by_stem[stem] = extract_cfgs_from_source(i_by_stem[stem]) or {}
                except Exception as exc:  # noqa: BLE001
                    _warn(
                        warnings,
                        f"{project}/{opt}: source CFG extraction failed for {stem}.i: {exc}",
                    )
                    src_by_stem[stem] = {}
            best = best_source_by_name(src_by_stem)

    out: dict[str, dict[str, MetricResult]] = {}
    for e in entries:
        src = resolved_source_for_binary(e.stem, src_by_stem, best) if needs_source else None
        try:
            out[e.stem] = evaluate_decompilation(e.result, src, metric_names)
        except Exception as exc:  # noqa: BLE001
            _warn(warnings, f"{project}/{opt}/{e.stem}: evaluation failed: {exc}")
    return out


def _next_steps(tree: Path, dec_id: str) -> str:
    """The exact follow-up commands to publish the new column."""
    reeval = ",".join((*_REEVAL_DEFAULTS, dec_id))
    bm_reeval = ",".join((*(d for d in _REEVAL_DEFAULTS if d not in _LLM_BASENAMES), dec_id))
    return (
        f"Next steps to publish '{dec_id}':\n"
        f"  1) refresh the type_match overlay from the updated checkpoints:\n"
        f"       python scripts/reeval_typematch.py {tree} --emit\n"
        f"  2) refresh the GED overlay with the new column included:\n"
        f"       DECBENCH_REEVAL_DECOMPILERS={reeval} \\\n"
        f"         python scripts/reeval_ged.py {tree}\n"
        f"  3) refresh the byte_match overlay (skip ONLY if you ingested with\n"
        f"     --evaluate and are content with the inline values; without this the\n"
        f"     published Compiles rate for the new column stays empty):\n"
        f"       DECBENCH_REEVAL_DECOMPILERS={bm_reeval} \\\n"
        f"         python scripts/reeval_bytematch.py {tree}\n"
        f"  4) canonical guarded rebuild of the derived files (+ --audit to check\n"
        f"     for silent coverage gaps):\n"
        f"       python scripts/finalize_results.py {tree}\n"
        f"  5) content edits (take effect on re-render, no re-run):\n"
        f'       - decbench/rendering/content/site.toml: add "{dec_id}" to\n'
        f"         [decompilers] sample_set_only\n"
        f"       - decbench/rendering/content/decompilers.toml: add a [[decompiler]]\n"
        f'         entry with id = "{dec_id}"\n'
        f"  6) cost facts: external submissions carry no timing/token data; re-run\n"
        f"     the cost-info writer so the data page stays consistent:\n"
        f"       python scripts/compute_cost_info.py {tree} llm_traces\n"
        f"  7) rebuild the site:\n"
        f"       decbench site build {tree} -o site/\n"
    )


def ingest_submission(
    submission: Path,
    tree: Path,
    dec_id: str,
    version: str | None = None,
    evaluate: bool = True,
    metrics: list[str] | None = None,
    force: bool = False,
) -> IngestSummary:
    """Ingest a packaged eval-kit submission as decompiler column ``dec_id``.

    ``submission`` is the packaged ``results.zip`` (or an unpacked directory
    holding the packaged ``results.json``); a raw un-packaged ``results.json``
    is rejected with instructions to run ``package.py``. ``force=True`` allows
    overwriting an existing ``dec_id`` column in the touched slices.
    """
    tree = Path(tree)
    if not tree.is_dir():
        raise EvalKitError(f"results tree not found: {tree}")
    if not _DEC_ID_RE.match(dec_id or ""):
        raise EvalKitError(
            f"invalid decompiler id {dec_id!r}: must match ^[a-z][a-z0-9-]*$ (no '@')"
        )

    from decbench.results_store import load_sample_manifest

    manifest = load_sample_manifest(tree)
    if manifest is None:
        raise EvalKitError(
            f"{tree} has no sample_set_manifest.json — external submissions are scoped "
            f"to the frozen sample-set and cannot be ingested without it"
        )

    warnings: list[str] = []
    counters = _Counters()
    entries: list[_Entry] = []

    with contextlib.ExitStack() as stack:
        payload, c_dir = _open_submission(Path(submission), stack)
        results = _require_packaged(payload)
        dataset = str(payload.get("dataset", "sample-set"))
        _check_manifest_drift(tree, payload, warnings)
        sub_dec = payload.get("decompiler")
        sub_version = sub_dec.get("version") if isinstance(sub_dec, dict) else None
        if version is None and isinstance(sub_version, str) and sub_version.strip():
            version = sub_version.strip()

        for c_name in sorted(results):
            built = _build_entry(
                tree,
                manifest,
                c_dir,
                c_name,
                results[c_name],
                dec_id,
                version,
                dataset,
                counters,
                warnings,
            )
            if built is not None:
                entries.append(built)

    if not entries:
        raise EvalKitError("no submission entry could be ingested (see warnings/log)")

    seen_slices: set[tuple[str, str, str]] = set()
    for e in entries:
        key = (e.project, e.opt, e.stem)
        if key in seen_slices:
            raise EvalKitError(f"submission covers {'/'.join(key)} twice — corrupt package")
        seen_slices.add(key)
    manifest_slices = {(p, o, b) for (p, o, b, _fn) in manifest}
    missing_slices = sorted(manifest_slices - seen_slices)
    if missing_slices:
        shown = ", ".join("/".join(m) for m in missing_slices[:8])
        more = " ..." if len(missing_slices) > 8 else ""
        _warn(
            warnings,
            f"submission covers {len(seen_slices)}/{len(manifest_slices)} manifest "
            f"binaries; none for: {shown}{more}",
        )

    by_project: dict[str, list[_Entry]] = {}
    for e in entries:
        by_project.setdefault(e.project, []).append(e)
    ckpt_dir = tree / "checkpoints"
    ckpts = {p: _load_checkpoint(ckpt_dir / f"{p}.pkl") for p in sorted(by_project)}
    conflicts: list[str] = []
    for project, ents in by_project.items():
        for e in ents:
            dsec = ckpts[project]["decompile"]
            okey = _opt_key(dsec, e.opt)
            if dec_id in (dsec.get(okey, {}).get(e.stem) or {}):
                conflicts.append(f"{project}/{e.opt}/{e.stem}")
    if conflicts and not force:
        raise EvalKitError(
            f"decompiler {dec_id!r} already ingested for: {', '.join(sorted(conflicts))} "
            f"— pass force=True (--force) to overwrite"
        )
    if conflicts:
        _l.info("force: overwriting %d existing %s slice(s)", len(conflicts), dec_id)
        _purge_stale_slices(tree, ckpts, dec_id, seen_slices, warnings)

    for e in entries:
        dec_out = tree / e.opt / e.project / "decompiled"
        dec_out.mkdir(parents=True, exist_ok=True)
        e.result.to_c_file(dec_out / f"{dec_id}_{e.stem}.c")
        e.result.to_toml(dec_out / f"{dec_id}_{e.stem}.toml")

    evals: dict[tuple[str, str], dict[str, dict[str, MetricResult]]] = {}
    if evaluate:
        import decbench.metrics  # noqa: F401 — register the metric plugins
        from decbench.metrics.registry import MetricRegistry

        metric_names = list(metrics) if metrics else MetricRegistry.list_registered()
        needs_source = any(MetricRegistry.get(m).requires_source_cfg for m in metric_names)
        groups: dict[tuple[str, str], list[_Entry]] = {}
        for e in entries:
            groups.setdefault((e.project, e.opt), []).append(e)
        for (project, opt), ents in sorted(groups.items()):
            evals[(project, opt)] = _evaluate_group(
                tree, project, opt, ents, metric_names, needs_source, warnings
            )

    # Re-read the checkpoint rather than reusing the pre-conflict-check copy: inline
    # evaluation can run for hours, and writing back the older snapshot would revert
    # anything a concurrent process checkpointed meanwhile.
    for project, ents in by_project.items():
        ckpt = _load_checkpoint(ckpt_dir / f"{project}.pkl")
        if conflicts:
            _purge_dec_slices(tree, project, ckpt, dec_id, seen_slices, None)
        for e in ents:
            dsec = ckpt["decompile"]
            okey = _opt_key(dsec, e.opt)
            dsec.setdefault(okey, {}).setdefault(e.stem, {})[dec_id] = e.result
            # Clear first, so a re-ingest with --no-evaluate cannot leave the previous
            # submission's numbers attached to the new code.
            esec = ckpt["evaluate"]
            ekey = _opt_key(esec, e.opt)
            esec.setdefault(ekey, {}).setdefault(e.stem, {}).pop(dec_id, None)
            metric_results = evals.get((project, e.opt), {}).get(e.stem)
            if metric_results:
                esec[ekey][e.stem][dec_id] = metric_results
        _write_checkpoint(ckpt_dir / f"{project}.pkl", ckpt)

    n_functions = sum(len(e.result.functions) for e in entries)
    n_failed = sum(len(e.result.decompiler.failed_functions) for e in entries)
    _l.info(
        "ingested %s: %d binaries, %d functions (%d relabeled, %d dropped, %d failed)",
        dec_id,
        len(entries),
        n_functions,
        counters.relabeled,
        counters.dropped_extra,
        n_failed,
    )
    return IngestSummary(
        dec_id=dec_id,
        n_binaries=len(entries),
        n_functions=n_functions,
        n_relabeled=counters.relabeled,
        n_dropped_extra=counters.dropped_extra,
        n_failed=n_failed,
        warnings=warnings,
        next_steps=_next_steps(tree, dec_id),
    )
