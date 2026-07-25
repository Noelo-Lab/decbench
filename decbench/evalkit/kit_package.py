#!/usr/bin/env python3
"""Validate a DecBench eval-kit submission and package it as ``results.zip``.

Run this from inside an unpacked DecBench eval kit (it lives at the kit root
as ``package.py``):

    python3 package.py [--out PATH] [--quiet]

It reads ``functions.json`` (shipped with the kit) and your submission in
``results/`` (``results.json`` + the ``.c`` files it lists), validates them,
de-anonymizes the binary references, and writes ``results.zip`` at the kit
root. Send back that zip — nothing else.

Exit status: 0 on success (warnings allowed; ``--quiet`` hides them),
1 on any validation error (all errors are printed, nothing is packaged).

This file is standalone on purpose: stdlib only, Python >= 3.8, no DecBench
imports — contributors run it with whatever ``python3`` they have.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

KIT_FORMAT_VERSION = 1

# results/ files that are part of the kit itself, not the submission.
_KIT_OWNED = {"README.md", "results.example.json", "results.json"}


def _no_dup_object_pairs(pairs: list) -> dict:
    """dict-builder for json.load that rejects duplicate keys (silent-loss guard)."""
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _load_json(path: Path) -> tuple:
    """(parsed, error) — error is a human-readable string when loading failed."""
    try:
        text = path.read_text()
    except OSError as e:
        return None, f"cannot read {path.name}: {e}"
    try:
        return json.loads(text, object_pairs_hook=_no_dup_object_pairs), None
    except ValueError as e:
        return None, f"cannot parse {path.name}: {e}"


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


def _word_present(text: str, word: str) -> bool:
    """Whether ``word`` occurs in ``text`` with identifier boundaries (no ``re``)."""
    start = 0
    n = len(word)
    while True:
        i = text.find(word, start)
        if i < 0:
            return False
        before = text[i - 1] if i > 0 else " "
        after = text[i + n] if i + n < len(text) else " "
        if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
            return True
        start = i + 1


def _public_addrs(functions_json: dict) -> dict:
    """Anon binary name -> set of target addresses (ints) from functions.json."""
    out: dict = {}
    public = functions_json.get("public")
    if isinstance(public, dict):
        for anon, addrs in public.items():
            parsed = set()
            if isinstance(addrs, list):
                for a in addrs:
                    p = _parse_addr(a)
                    if p is not None:
                        parsed.add(p)
            out[str(anon)] = parsed
    return out


def validate_and_package(kit_root: Path, out_path: Path | None = None, quiet: bool = False) -> int:
    """Validate the submission under ``kit_root`` and write the results zip.

    Returns the process exit code (0 = packaged, 1 = validation errors).
    """
    errors: list = []
    warnings: list = []

    functions_path = kit_root / "functions.json"
    results_dir = kit_root / "results"
    results_path = results_dir / "results.json"

    functions_json, err = _load_json(functions_path)
    if err is not None or not isinstance(functions_json, dict):
        reason = err or "functions.json is not a JSON object"
        print(f"error: {reason} — run this script from inside an unpacked kit", file=sys.stderr)
        return 1
    public = _public_addrs(functions_json)
    private = functions_json.get("private")
    private = private if isinstance(private, dict) else {}

    if not results_path.is_file():
        print(
            f"error: {results_path} not found — write your submission first "
            "(see results/README.md)",
            file=sys.stderr,
        )
        return 1
    submission, err = _load_json(results_path)
    if err is not None:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if not isinstance(submission, dict):
        print("error: results.json must be a JSON object", file=sys.stderr)
        return 1

    dec = submission.get("decompiler")
    dec_name = dec.get("name") if isinstance(dec, dict) else None
    dec_version = dec.get("version") if isinstance(dec, dict) else None
    if not isinstance(dec_name, str) or not dec_name.strip():
        errors.append('results.json: "decompiler" must be an object with a non-empty "name"')
        dec_name = "unknown"

    entries = submission.get("results")
    if not isinstance(entries, dict) or not entries:
        errors.append('results.json: "results" must be a non-empty object mapping .c files')
        entries = {}

    packaged: dict = {}
    covered_binaries: dict = {}  # anon binary -> .c file claiming it
    covered_addrs: dict = {}  # anon binary -> set of claimed addresses
    listed_c: set = set()
    n_functions = 0

    for c_name in sorted(entries):
        entry = entries[c_name]
        where = f"results.json[{c_name!r}]"
        if Path(c_name).name != c_name or not c_name.endswith(".c"):
            errors.append(f"{where}: keys must be plain .c filenames (no directories)")
            continue
        listed_c.add(c_name)
        c_path = results_dir / c_name
        if not c_path.is_file():
            errors.append(f"{where}: listed file results/{c_name} is missing")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where}: entry must be an object")
            continue

        anon = entry.get("binary")
        if not isinstance(anon, str) or anon not in public:
            errors.append(
                f"{where}: unknown binary {anon!r} (must be one of the kit's binaries/ names)"
            )
            continue
        if anon in covered_binaries:
            errors.append(
                f"{where}: binary {anon} already covered by {covered_binaries[anon]} "
                "(one .c per binary)"
            )
            continue
        covered_binaries[anon] = c_name

        funcs = entry.get("functions")
        if not isinstance(funcs, dict) or not funcs:
            errors.append(f'{where}: "functions" must be a non-empty object')
            continue

        c_text = c_path.read_text(errors="replace")
        out_funcs: dict = {}
        seen_addrs: dict = {}
        for fn_name in sorted(funcs):
            if not isinstance(fn_name, str) or not fn_name.isidentifier():
                errors.append(f"{where}: {fn_name!r} is not a valid C identifier")
                continue
            addr = _parse_addr(funcs[fn_name])
            if addr is None:
                errors.append(
                    f"{where}: {fn_name} has an unparseable address {funcs[fn_name]!r} "
                    '(use a hex string like "0x1234")'
                )
                continue
            # ARM/Thumb tools report entry points with the low bit set; the kit
            # README promises the odd form is tolerated, so normalize to the
            # even target instead of rejecting it (ingest applies the same rule).
            if addr not in public[anon] and (addr & ~1) in public[anon]:
                addr &= ~1
            if addr not in public[anon]:
                errors.append(
                    f"{where}: {fn_name} -> 0x{addr:x} is not a target address of {anon} "
                    "(see functions.json public)"
                )
                continue
            if addr in seen_addrs:
                errors.append(
                    f"{where}: address 0x{addr:x} claimed by both "
                    f"{seen_addrs[addr]} and {fn_name}"
                )
                continue
            seen_addrs[addr] = fn_name
            if not _word_present(c_text, fn_name):
                warnings.append(f"{where}: identifier {fn_name} not found in results/{c_name}")
            out_funcs[fn_name] = f"0x{addr:x}"
        # (duplicate function names within one file are impossible past JSON
        # parsing — the duplicate-key hook rejects them at load time)

        covered_addrs[anon] = set(seen_addrs)
        n_functions += len(out_funcs)
        identity = private.get(anon)
        identity = identity if isinstance(identity, dict) else {}
        packaged[c_name] = {
            "binary": {k: identity.get(k) for k in ("project", "opt", "binary", "file")},
            "anon_binary": anon,
            "functions": out_funcs,
        }

    # Coverage + stray-file warnings (never fatal). Partial submissions are
    # explicitly allowed, so uncovered binaries are summarized in ONE line — a
    # per-binary warning would bury the real ones under hundreds of lines.
    uncovered = sorted(set(public) - set(covered_binaries))
    if uncovered:
        shown = ", ".join(uncovered[:5])
        more = f", ... and {len(uncovered) - 5} more" if len(uncovered) > 5 else ""
        warnings.append(
            f"no submission for {len(uncovered)} of {len(public)} kit binaries ({shown}{more})"
        )
    partial = []
    for anon in sorted(covered_addrs):
        missing = sorted(public[anon] - covered_addrs[anon])
        if missing:
            joined = ", ".join(f"0x{a:x}" for a in missing)
            partial.append(f"{anon} ({joined})")
    if partial:
        shown = "; ".join(partial[:5])
        more = f"; ... and {len(partial) - 5} more" if len(partial) > 5 else ""
        warnings.append(
            f"{len(partial)} submitted binar{'y' if len(partial) == 1 else 'ies'} "
            f"missing some target addresses: {shown}{more}"
        )
    if results_dir.is_dir():
        for entry_path in sorted(results_dir.iterdir()):
            if entry_path.name not in _KIT_OWNED and entry_path.name not in listed_c:
                warnings.append(f"stray file in results/ (not packaged): {entry_path.name}")

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"{len(errors)} error(s) — nothing packaged.", file=sys.stderr)
        return 1
    if not quiet:
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)

    out_json = {
        "kit_format_version": functions_json.get("kit_format_version", KIT_FORMAT_VERSION),
        "dataset": functions_json.get("dataset", "sample-set"),
        # Carried through so ingest can detect that the benchmark's frozen
        # manifest was re-drawn after this kit was exported.
        "manifest_sha256": functions_json.get("manifest_sha256"),
        "packaged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "decompiler": {"name": dec_name, "version": dec_version},
        "results": packaged,
    }
    zip_path = out_path if out_path is not None else kit_root / "results.zip"
    with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("results.json", json.dumps(out_json, indent=2) + "\n")
        for c_name in sorted(packaged):
            zf.write(str(results_dir / c_name), arcname=c_name)

    total_addrs = sum(len(a) for a in public.values())
    print(f"packaged {len(packaged)} .c file(s) -> {zip_path}")
    print(
        f"binaries covered {len(covered_binaries)}/{len(public)}, "
        f"functions {n_functions}/{total_addrs}"
    )
    return 0


def main(argv: list | None = None) -> int:
    """CLI entry point: parse args, then validate + package the kit."""
    parser = argparse.ArgumentParser(
        description="Validate a DecBench eval-kit submission and package results.zip."
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="write the zip here instead of <kit>/results.zip"
    )
    parser.add_argument("--quiet", action="store_true", help="suppress warnings")
    args = parser.parse_args(argv)
    kit_root = Path(__file__).resolve().parent
    return validate_and_package(kit_root, out_path=args.out, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
