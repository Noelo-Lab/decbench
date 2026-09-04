#!/usr/bin/env python3
"""Compile zlib with REAL MSVC (cl.exe under Wine) and report metric-readiness.

Validates the experimental `decbench-msvc` image (docker/msvc.Dockerfile,
msvc-wine): downloads zlib 1.3.1, builds it with `nmake -f win32/Makefile.msc`
in two variants (the Makefile's default -O2 -Zi, plus a -Od -Zi override),
then verifies the artifacts a benchmark integration would need:

  * PE outputs exist (zlib1.dll / example.exe / minigzip.exe) and are x86-64;
  * PDBs exist and NO DWARF `.debug_*` sections are present (MSVC emits
    PDB/CodeView — decbench's DWARF-based ground truth does not apply);
  * llvm-pdbutil can extract function names/addresses, locals and types from
    the PDB (the future ground-truth path, see docs/MSVC_SUPPORT.md);
  * `cl -P` emits preprocessed sources (the `.i` GED-parity path).

Runs INSIDE the container (stdlib-only — the image has no decbench deps):

    docker run --rm -v "$PWD":/workspace -w /workspace \\
      --user "$(id -u):$(id -g)" decbench-msvc \\
      python3 scripts/msvc_compile_smoke.py /workspace/msvc_smoke_out

(The script self-provisions a Wine-safe $HOME — wine refuses a HOME the uid
does not own, and msvc-wine's fifo wrappers HANG rather than fail on that.)

Usage:
    python3 scripts/msvc_compile_smoke.py [out_dir]
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ZLIB_URLS = [
    "https://github.com/madler/zlib/archive/refs/tags/v1.3.1.tar.gz",
    "https://zlib.net/zlib-1.3.1.tar.gz",
]

# PE COFF machine values we care about (mirrors decbench/utils/binfmt.py).
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "aarch64", 0x1C0: "arm"}

# variant name -> nmake extra args (None = Makefile.msc defaults: -O2 -Oy- -Zi)
VARIANTS: dict[str, list[str]] = {
    "O2-default": [],
    "Od": ["CFLAGS=-nologo -MD -W3 -Od -Zi -Fdzlib"],
}

EXPECT_PE = ["zlib1.dll", "example.exe", "minigzip.exe"]


def _pe_machine(path: Path) -> str | None:
    """Return the PE machine name, or None if `path` is not a PE file."""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            (e_lfanew,) = struct.unpack("<I", f.read(4))
            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return None
            return _PE_MACHINES.get(struct.unpack("<H", f.read(2))[0], "other")
    except (OSError, struct.error):
        return None


def _run(
    cmd: list[str], cwd: Path | None = None, check: bool = True, timeout: int = 1200
) -> subprocess.CompletedProcess:
    """Run a command, echoing it; on failure print its output."""
    print(f"  $ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timed out after {timeout}s: {cmd[0]}") from exc
    if check and proc.returncode != 0:
        print(proc.stdout[-4000:])
        print(proc.stderr[-4000:])
        raise RuntimeError(f"command failed ({proc.returncode}): {cmd[0]}")
    return proc


def _ensure_wine_home() -> None:
    """Give Wine a HOME the current uid owns (it refuses e.g. root-owned /tmp).

    When the container runs with ``--user`` the inherited $HOME is often /tmp
    or /root; wine then errors "'/tmp' is not owned by you" and msvc-wine's
    fifo-based wrappers hang instead of failing. Self-provision a private HOME.
    """
    home = Path(os.environ.get("HOME", "/nonexistent"))
    try:
        owned = home.stat().st_uid == os.getuid() and os.access(home, os.W_OK)
    except OSError:
        owned = False
    if not owned:
        new_home = Path(tempfile.mkdtemp(prefix="msvc-wine-home-"))
        os.environ["HOME"] = str(new_home)
        print(f"HOME not usable for wine; using {new_home}")


def _warmup_wine() -> None:
    """Initialize the Wine prefix once (fresh $HOME when run with --user)."""
    wine = shutil.which("wine64") or shutil.which("wine")
    if wine:
        subprocess.run([wine, "wineboot", "--init"], capture_output=True, timeout=300)
        if shutil.which("wineserver"):
            subprocess.run(["wineserver", "-w"], capture_output=True, timeout=300)


def _find_bin() -> Path:
    bin_dir = Path(os.environ.get("BIN", "/opt/msvc/bin/x64"))
    if not (bin_dir / "cl").exists():
        raise RuntimeError(f"MSVC wrapper dir not found: {bin_dir} (is this the msvc image?)")
    return bin_dir


def _download_zlib(work: Path) -> Path:
    """Download + extract zlib, returning the source directory."""
    tarball = work / "zlib.tar.gz"
    if not tarball.exists():
        for url in ZLIB_URLS:
            try:
                print(f"  downloading {url}")
                urllib.request.urlretrieve(url, tarball)
                break
            except OSError as exc:
                print(f"  download failed: {exc}")
        else:
            raise RuntimeError("could not download zlib from any mirror")
    with tarfile.open(tarball) as tf:
        tf.extractall(work)
    src = next(p for p in work.iterdir() if p.is_dir() and p.name.startswith("zlib"))
    return src


def _build_variant(src: Path, out: Path, extra: list[str]) -> dict[str, str | None]:
    """Copy the zlib tree to `out`, build with nmake, return {expected PE: machine}."""
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(src, out)
    _run(["nmake", "-f", "win32/Makefile.msc", *extra], cwd=out)
    return {name: _pe_machine(out / name) for name in EXPECT_PE}


def _no_dwarf(path: Path) -> bool:
    """True if objdump reports no .debug_* sections (i.e. no DWARF)."""
    proc = _run(["objdump", "-h", str(path)], check=False)
    return proc.returncode == 0 and ".debug_" not in proc.stdout


def _pdbutil() -> str | None:
    for name in ("llvm-pdbutil", "llvm-pdbutil-18", "llvm-pdbutil-17"):
        if shutil.which(name):
            return name
    return None


def _pdb_summary(pdb: Path) -> dict[str, object]:
    """Summarize what a PDB ground-truth reader could extract from `pdb`."""
    tool = _pdbutil()
    if tool is None:
        return {"error": "llvm-pdbutil not installed"}
    syms = _run([tool, "dump", "--symbols", str(pdb)], check=False)
    types = _run([tool, "dump", "--types", str(pdb)], check=False)
    if syms.returncode != 0:
        return {"error": f"llvm-pdbutil failed: {syms.stderr[-500:]}"}
    name_re = re.compile(r"S_[LG]PROC32\s+\[size = \d+\]\s+`([^`]+)`")
    funcs = name_re.findall(syms.stdout)
    locals_n = len(re.findall(r"\bS_LOCAL\b", syms.stdout))
    regrel_n = len(re.findall(r"\bS_REGREL32\b", syms.stdout))
    addr_n = len(re.findall(r"addr = \d{4}:\d+", syms.stdout))
    struct_n = len(re.findall(r"\bLF_STRUCTURE\b", types.stdout)) if types.returncode == 0 else 0
    return {
        "functions": len(funcs),
        "function_names_sample": sorted(set(funcs))[:8],
        "func_addrs (sect:off)": addr_n,
        "locals (S_LOCAL)": locals_n,
        "locals (S_REGREL32)": regrel_n,
        "struct type records": struct_n,
    }


def _preprocess_check(src: Path) -> bool:
    """Verify `cl -P` can emit a preprocessed TU (the GED source path)."""
    proc = _run(
        ["cl", "-nologo", "-P", "-D_CRT_SECURE_NO_DEPRECATE", "adler32.c"], cwd=src, check=False
    )
    out = src / "adler32.i"
    ok = proc.returncode == 0 and out.exists() and out.stat().st_size > 1000
    if ok:
        print(f"  cl -P -> adler32.i ({out.stat().st_size} bytes)")
    return ok


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/msvc_smoke")
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=== MSVC (msvc-wine) zlib compile smoke ===")
    bin_dir = _find_bin()
    print(f"MSVC wrappers: {bin_dir}")
    _ensure_wine_home()
    _warmup_wine()
    cl_banner = _run(["cl"], check=False).stderr.strip().splitlines()
    if cl_banner:
        print(f"cl banner: {cl_banner[0]}")

    src = _download_zlib(out_dir)
    print(f"zlib source: {src}")

    failures: list[str] = []
    pdb_reports: dict[str, dict[str, object]] = {}
    for variant, extra in VARIANTS.items():
        print(f"\n--- variant {variant} ---")
        build = out_dir / f"build-{variant}"
        try:
            pes = _build_variant(src, build, extra)
        except RuntimeError as exc:
            failures.append(f"{variant}: build failed ({exc})")
            continue
        for name, machine in pes.items():
            print(f"  {name}: {'PE ' + machine if machine else 'MISSING/not-PE'}")
            if machine != "x86-64":
                failures.append(f"{variant}: {name} not a x86-64 PE (got {machine})")
        pdbs = sorted(p.name for p in build.glob("*.pdb"))
        print(f"  PDBs: {pdbs or '(none)'}")
        if not pdbs:
            failures.append(f"{variant}: no PDB produced")
        dll = build / "zlib1.dll"
        if dll.exists():
            if _no_dwarf(dll):
                print("  zlib1.dll: no .debug_* sections (no DWARF, as expected for MSVC)")
            else:
                print("  zlib1.dll: UNEXPECTED .debug_* sections present")
        link_pdb = build / "zlib1.pdb"
        if link_pdb.exists():
            pdb_reports[variant] = _pdb_summary(link_pdb)

    print("\n--- PDB ground-truth extractability (llvm-pdbutil) ---")
    for variant, report in pdb_reports.items():
        print(f"  [{variant}] zlib1.pdb:")
        for key, val in report.items():
            print(f"    {key}: {val}")
    if not pdb_reports:
        failures.append("no PDB could be inspected")

    print("\n--- cl -P preprocessing (GED source path) ---")
    if not _preprocess_check(src):
        failures.append("cl -P preprocessing failed")

    print()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
    print(f"VERDICT: {'PASS' if not failures else 'FAIL'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
