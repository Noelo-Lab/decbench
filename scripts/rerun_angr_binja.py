#!/usr/bin/env python
"""Re-run ONLY angr + binja across an existing results tree, refreshing all three
metrics, and leaving every other decompiler's data untouched.

Why: the decbench env was rebuilt on Python 3.14, which only affects the two
Python-driven backends (angr — a pure-Python decompiler — and Binary Ninja,
driven via its headless Python API). Ghidra (JVM), IDA (idalib) and any historical
kuna data are unaffected, so we re-decompile just angr + binja and re-score their
GED / type_match / byte_match, then rebuild the report from the merged dataset.

This mirrors the proven ``rerun_binja.sh`` flow but (a) covers both angr and binja,
(b) recomputes byte_match for them too (their output can change), and (c) writes a
machine-readable stage-timeline status file (``<root>/rerun_ab_status.json``) that
``scripts/run_progress.py`` renders live. Every stage is resumable — the reeval
checkpoints and per-project decompile checkpoints survive a crash/restart.

The "decompilation cache" for angr + binja is invalidated three ways:
  * their per-project decompile results are force-redone (DECBENCH_REDO_DECOMPILERS)
    and the ``decompiled/{angr,binja}_*.c`` artifacts overwritten in place;
  * their per-(binary) GED/byte_match reeval checkpoints are deleted so those
    metrics recompute from the fresh .c;
  * the content-addressed metric cache self-invalidates (its key includes the
    decompiled content, so changed output misses and recomputes).

Usage:  python scripts/rerun_angr_binja.py [results/full_run]
Env:    GHIDRA_INSTALL_DIR (for the ghidra backend used during discovery),
        DECBENCH_WORKERS (decompile pool, default 24),
        DECBENCH_GED_WORKERS (default 16), DECBENCH_BM_WORKERS (default 32).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

DECS = ["angr", "binja"]
STAGE_ORDER = [
    "snapshot",
    "decompile",
    "restore",
    "reeval_ged",
    "reeval_typematch",
    "reeval_bytematch",
    "rebuild",
    "render",
    "done",
]

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PY = sys.executable
BIN_DIR = Path(PY).parent
DECBENCH_BIN = BIN_DIR / "decbench"


class Orchestrator:
    def __init__(self, root: Path) -> None:
        self.root = root
        # Parametrization (env-driven) so the same flow can do a scoped fix run,
        # e.g. re-decompile only angr on the timeout-truncated large projects with
        # a bigger per-binary budget:
        #   RERUN_DECS=angr RERUN_ONLY_PROJECTS=bash,betaflight,... \
        #   RERUN_DECOMPILE_TIMEOUT=3600 python scripts/rerun_angr_binja.py
        self.decs = [d for d in (os.environ.get("RERUN_DECS") or ",".join(DECS)).split(",") if d]
        self.projects = [
            p for p in (os.environ.get("RERUN_ONLY_PROJECTS") or "").split(",") if p
        ]
        self.dec_timeout = os.environ.get("RERUN_DECOMPILE_TIMEOUT") or ""
        self.status_path = root / "rerun_ab_status.json"
        self.log_path = root / "rerun_angr_binja.log"
        self.logf = open(self.log_path, "a", buffering=1)
        self.status = {
            "run_start": time.time(),
            "decompilers": self.decs,
            "only_projects": self.projects,
            "decompile_timeout": self.dec_timeout or "300",
            "log": str(self.log_path),
            "stage_order": STAGE_ORDER,
            "current": None,
            "stages": {},
            "workers": {
                "decompile": int(os.environ.get("DECBENCH_WORKERS") or "24"),
                "ged": int(os.environ.get("DECBENCH_GED_WORKERS") or "16"),
                "bytematch": int(os.environ.get("DECBENCH_BM_WORKERS") or "32"),
            },
        }
        self._write_status()

    # -- status + logging ----------------------------------------------------
    def _write_status(self) -> None:
        tmp = self.status_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.status, indent=2))
        os.replace(tmp, self.status_path)

    def emit(self, msg: str) -> None:
        line = f"[orchestrator {time.strftime('%H:%M:%S')}] {msg}"
        print(line, file=self.logf, flush=True)
        print(line, flush=True)

    def start_stage(self, name: str) -> None:
        self.status["current"] = name
        self.status["stages"][name] = {"start": time.time(), "end": None}
        self._write_status()
        self.emit(f"=== STAGE {name} START ===")

    def end_stage(self, name: str) -> None:
        self.status["stages"][name]["end"] = time.time()
        self._write_status()
        dur = self.status["stages"][name]["end"] - self.status["stages"][name]["start"]
        self.emit(f"=== STAGE {name} DONE in {dur:.0f}s ===")

    # -- subprocess runner ---------------------------------------------------
    def run(self, cmd: list[str], extra_env: dict[str, str] | None = None) -> None:
        env = dict(os.environ)
        env.setdefault("PYTHONWARNINGS", "ignore")
        if extra_env:
            env.update(extra_env)
        self.emit("$ " + " ".join(cmd))
        rc = subprocess.run(
            cmd, cwd=str(REPO), env=env, stdout=self.logf, stderr=subprocess.STDOUT
        ).returncode
        if rc != 0:
            raise RuntimeError(f"command failed (rc={rc}): {' '.join(cmd)}")

    # -- stages --------------------------------------------------------------
    def stage_snapshot(self) -> None:
        self.start_stage("snapshot")
        for src, dst in (
            ("function_results.json", "function_results.beforeAB.json"),
            ("scoreboard.toml", "scoreboard.beforeAB.toml"),
        ):
            s = self.root / src
            if s.exists():
                shutil.copy2(s, self.root / dst)
                self.emit(f"snapshotted {src} -> {dst}")
        self.end_stage("snapshot")

    def stage_decompile(self) -> None:
        self.start_stage("decompile")
        w = self.status["workers"]["decompile"]
        # Re-decompile the target decompilers; force-redo so their existing results
        # are overwritten. DECOMPILE_ONLY skips the redundant inline Joern eval (a
        # dedicated reeval_ged pass rescoring the fresh .c follows). Other
        # decompilers in each checkpoint are preserved & merged. When scoped to a
        # project subset (self.projects) the run_benchmark `-- <projects>` filter
        # limits work to just those; a larger DECBENCH_DECOMPILE_TIMEOUT gives slow
        # backends (angr) room to finish large binaries that previously timed out.
        cmd = [PY, str(HERE / "run_benchmark.py"), str(self.root)]
        if self.projects:
            cmd += ["--", *self.projects]
        env = {
            "DECBENCH_DECOMPILERS": ",".join(self.decs),
            "DECBENCH_REDO_DECOMPILERS": ",".join(self.decs),
            "DECBENCH_DECOMPILE_ONLY": "1",
            "DECBENCH_WORKERS": str(w),
        }
        if self.dec_timeout:
            env["DECBENCH_DECOMPILE_TIMEOUT"] = self.dec_timeout
        self.run(cmd, extra_env=env)
        self.end_stage("decompile")

    def stage_restore(self) -> None:
        # run_benchmark rewrites function_results.json/scoreboard.toml from its
        # (now-empty, DECOMPILE_ONLY) evals; restore the good pre-run dataset so
        # the reeval + rebuild chain has the correct base to merge into.
        self.start_stage("restore")
        for snap, dst in (
            ("function_results.beforeAB.json", "function_results.json"),
            ("scoreboard.beforeAB.toml", "scoreboard.toml"),
        ):
            s = self.root / snap
            if s.exists():
                shutil.move(str(s), str(self.root / dst))
                self.emit(f"restored {dst} from {snap}")
        self.end_stage("restore")

    def _drop_reeval_ckpts(self, subdir: str) -> None:
        # Drop only the checkpoints we intend to recompute. Scoped to (dec) and,
        # when self.projects is set, to those projects — leaving every other
        # (project, dec) checkpoint intact. The reeval scripts still MERGE ALL
        # surviving checkpoints into the emitted *_new.json, so the merged file
        # stays COMPLETE (no project is dropped from GED/byte_match at rebuild).
        d = self.root / subdir
        if not d.is_dir():
            return
        n = 0
        projglobs = [f"*__{p}__*" for p in self.projects] if self.projects else ["*"]
        for dec in self.decs:
            for pg in projglobs:
                for f in d.glob(f"{pg}__{dec}.json"):
                    f.unlink()
                    n += 1
        scope = f"projects={self.projects}" if self.projects else "all projects"
        self.emit(f"dropped {n} stale {subdir} checkpoints for {self.decs} ({scope})")

    def stage_reeval_ged(self) -> None:
        self.start_stage("reeval_ged")
        self._drop_reeval_ckpts("reeval_ged")
        cmd = [PY, str(HERE / "reeval_ged.py"), str(self.root),
               str(self.status["workers"]["ged"]), *self.projects]
        self.run(cmd)
        self.end_stage("reeval_ged")

    def stage_reeval_typematch(self) -> None:
        self.start_stage("reeval_typematch")
        # Recomputes type_match from the run checkpoints for the target projects
        # (all projects if unscoped). update_type_match at rebuild is ADDITIVE
        # (it only sets where a fresh value exists), so scoping is safe — untouched
        # projects keep their existing type_match. Emits type_match_new.json.
        cmd = [PY, str(HERE / "reeval_typematch.py"), str(self.root), "--emit", *self.projects]
        self.run(cmd)
        self.end_stage("reeval_typematch")

    def stage_reeval_bytematch(self) -> None:
        self.start_stage("reeval_bytematch")
        self._drop_reeval_ckpts("reeval_bm")
        cmd = [PY, str(HERE / "reeval_bytematch.py"), str(self.root),
               str(self.status["workers"]["bytematch"]), *self.projects]
        self.run(cmd)
        self.end_stage("reeval_bytematch")

    def stage_rebuild(self) -> None:
        self.start_stage("rebuild")
        # FIRST rebuild the decompiled universe from the FRESH checkpoints, so a
        # re-decompile that RECOVERED functions (force-decompile of missed DWARF
        # targets, a new backend binary) actually shows them as decompiled and the
        # phantom-row guard is applied. rebuild_function_data only MERGES metric
        # values into existing rows — it never adds a recovered function or flips
        # decompiled status — so without this the recovered functions would be
        # invisible in function_results.json.
        self.run([PY, str(HERE / "rebuild_dataset_from_checkpoints.py"), str(self.root)])
        rb = str(HERE / "rebuild_function_data.py")
        # Then merge each recomputed metric into function_results.json. byte_match
        # runs LAST in default mode so it refreshes compile_rates + samples/hardest
        # + the scoreboard from the fully-updated dataset.
        self.run([PY, rb, str(self.root), "--ged"])
        self.run([PY, rb, str(self.root), "--type-match"])
        self.run([PY, rb, str(self.root)])
        self.end_stage("rebuild")

    def stage_render(self) -> None:
        self.start_stage("render")
        report = self.root / "report.html"
        self.run([str(DECBENCH_BIN), "report", str(self.root / "scoreboard.toml"),
                  "-o", str(report)])
        self.end_stage("render")

    def run_all(self) -> int:
        scope = f", projects={self.projects}" if self.projects else ""
        tmo = f", timeout={self.dec_timeout}s" if self.dec_timeout else ""
        self.emit(
            f"re-run of {self.decs} over {self.root}{scope}{tmo} "
            f"— workers={self.status['workers']}"
        )
        try:
            # RERUN_SKIP_DECOMPILE: the decompiled artifacts + checkpoints are
            # already correct on disk (e.g. after an in-place relabel fix); just
            # re-score + rebuild from them. No snapshot/decompile/restore needed
            # (nothing clobbers function_results.json), so it stays the merge base.
            if os.environ.get("RERUN_SKIP_DECOMPILE") != "1":
                self.stage_snapshot()
                self.stage_decompile()
                self.stage_restore()
            else:
                self.emit("SKIP_DECOMPILE: re-scoring from existing artifacts")
            self.stage_reeval_ged()
            self.stage_reeval_typematch()
            self.stage_reeval_bytematch()
            self.stage_rebuild()
            self.stage_render()
        except Exception as e:  # noqa: BLE001
            self.emit(f"FAILED: {type(e).__name__}: {e}")
            self.status["current"] = "failed"
            self.status["error"] = str(e)
            self._write_status()
            return 1
        self.status["current"] = "done"
        self._write_status()
        self.emit(f"ALL DONE. report: {self.root / 'report.html'}")
        return 0


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/full_run")
    if not root.is_dir():
        print(f"results dir not found: {root}", file=sys.stderr)
        return 2
    return Orchestrator(root).run_all()


if __name__ == "__main__":
    raise SystemExit(main())
