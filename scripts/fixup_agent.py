"""Build each decompiler's byte-match fixup with a time-boxed coding agent.

Every decompiler gets the same treatment: one prompt
(``decbench/metrics/fixups/PROMPT.md``), one model, one wall-clock budget, one
sandbox, and the same development split of the corpus. The agent writes a
single ``fixup.py`` (contract: :mod:`decbench.metrics.fixups`) that is then
installed as ``decbench/metrics/fixups/generated/<decompiler>.py`` for human
review.

Steps::

    # 1. Export one decompiler's functions from a results tree, scored raw.
    python scripts/fixup_agent.py dataset results/<tree> -d ghidra -o fixup_data
    # 2. Let the agent work for at most --minutes, then score it on the held-out
    #    split and install the module (+ its NOTES.md) into the package.
    python scripts/fixup_agent.py run -d ghidra --data fixup_data --runs fixup_runs
    # 3. List what the agent ran, flagging anything that reached outside its workspace.
    python scripts/fixup_agent.py audit fixup_runs/ghidra

Only x86 functions whose recompile toolchain exists are exported, and malware
projects never are. The split is by project: a project is held out when
``sha256("decbench-fixup:" + name) % 4 == 0``.

The agent is Codex CLI under ``bwrap``, in its own PID namespace: ``$HOME`` and
``/tmp`` are replaced by empty tmpfs mounts, and only the Python install, the
virtualenv, the Node/Codex install, and the run directory (holding a read-only
copy of ``decbench/`` without any per-decompiler fixup) are bound back in, so
the agent cannot read the corpus sources, the results tree, the held-out split,
other fixups, or any git history. Codex authenticates from a copy of
``~/.codex/auth.json`` in a per-run ``CODEX_HOME``. If the agent stops early it
is resumed with the same continuation message until the budget is spent.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import multiprocessing as mp
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import toml

REPO = Path(__file__).resolve().parents[1]
PROMPT = REPO / "decbench" / "metrics" / "fixups" / "PROMPT.md"
FIXUPS = REPO / "decbench" / "metrics" / "fixups"
HELDOUT_MODULUS = 4
MIN_RESUME_SECONDS = 600
MAX_IDLE_RESUMES = 2
DISABLED_FEATURES = (
    "multi_agent",
    "multi_agent_v2",
    "apps",
    "browser_use",
    "browser_use_external",
    "in_app_browser",
    "computer_use",
    "image_generation",
)
CONTINUE = (
    "You still have about {minutes} minutes of your budget. Keep improving fixup.py "
    "under the same rules, starting from the largest remaining error clusters and the "
    "compiled functions that differ most from the original, and run a full eval before "
    "you stop. Update NOTES.md for any new rule category."
)
TEMPLATE = '''"""Compilability fixup for {decompiler} output. See NOTES.md."""

FLAGS: list[str] = []


def prepare(code, ctx):
    return code
'''


def is_heldout(project: str) -> bool:
    digest = hashlib.sha256(f"decbench-fixup:{project}".encode()).hexdigest()
    return int(digest, 16) % HELDOUT_MODULUS == 0


def malware_projects() -> set[str]:
    names = set()
    for path in (REPO / "projects").rglob("*.toml"):
        try:
            data = toml.loads(path.read_text())
        except (OSError, toml.TomlDecodeError):
            continue
        if data.get("is_malware"):
            names.add(data.get("name") or path.stem)
    return names


def _export_binary(task: tuple[str, str, str, str, str, str]) -> dict[str, Any] | None:
    opt, project, stem, dec, binary_path, c_path = task
    from decbench.metrics.byte_match import recompile_inputs, score_function
    from decbench.utils.results_tree import split_functions

    funcs = split_functions(Path(c_path))
    siblings = {name: code for name, (_addr, code) in funcs.items()}
    group: dict[str, Any] = {"group": f"{opt}/{project}/{stem}", "siblings": siblings, "funcs": []}
    for name, (addr, code) in funcs.items():
        inputs = recompile_inputs(Path(binary_path), name, addr)
        if not isinstance(inputs, tuple):
            continue
        compiler, flags, arch_mode, orig = inputs
        if arch_mode is None:
            continue
        group.setdefault("compiler", compiler)
        group.setdefault("flags", flags)
        group.setdefault("cs", list(arch_mode))
        raw = score_function(code, name, addr, orig, compiler, flags, arch_mode, siblings=siblings)
        group["funcs"].append(
            {
                "name": name,
                "address": addr,
                "orig": orig.hex(),
                "raw_ok": bool((raw.metadata or {}).get("compilable")),
                "raw_bm": float(raw.value),
            }
        )
    return group if group["funcs"] else None


def cmd_dataset(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(REPO / "scripts"))
    import reeval_bytematch

    reeval_bytematch.DECOMPILERS = (args.decompiler,)
    excluded = malware_projects()
    tasks = [
        t
        for t in reeval_bytematch.build_tasks(Path(args.results), only=set(args.project) or None)
        if not any(t[1] == m or t[1].startswith(f"{m}-") for m in excluded)
    ]
    out = Path(args.out) / args.decompiler
    out.mkdir(parents=True, exist_ok=True)
    counts = {"dev": [0, 0], "heldout": [0, 0]}
    projects: dict[str, set[str]] = {"dev": set(), "heldout": set()}
    with (
        gzip.open(out / "dev.jsonl.gz", "wt") as dev,
        gzip.open(out / "heldout.jsonl.gz", "wt") as held,
        mp.get_context("spawn").Pool(args.workers) as pool,
    ):
        for i, group in enumerate(pool.imap_unordered(_export_binary, tasks), 1):
            if group is not None:
                split = "heldout" if is_heldout(group["group"].split("/")[1]) else "dev"
                (held if split == "heldout" else dev).write(json.dumps(group) + "\n")
                counts[split][0] += len(group["funcs"])
                counts[split][1] += sum(f["raw_ok"] for f in group["funcs"])
                projects[split].add(group["group"].split("/")[1])
            if i % 50 == 0 or i == len(tasks):
                print(f"[dataset] {i}/{len(tasks)} binaries", flush=True)
    meta = {
        "decompiler": args.decompiler,
        "results": str(Path(args.results).resolve()),
        "excluded_projects": sorted(excluded),
        **{
            split: {
                "functions": n,
                "raw_compile_rate": ok / (n or 1),
                "projects": sorted(projects[split]),
            }
            for split, (n, ok) in counts.items()
        },
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))
    return 0


def snapshot_package(dest: Path) -> Path:
    """Copy ``decbench/`` for the agent, minus every per-decompiler fixup module."""
    keep = {"__init__.py", "workbench.py", "PROMPT.md"}

    def ignore(directory: str, names: list[str]) -> set[str]:
        dropped = {n for n in names if n == "__pycache__"}
        if Path(directory).resolve() == FIXUPS.resolve():
            dropped |= {n for n in names if n not in keep}
        return dropped

    shutil.copytree(REPO / "decbench", dest / "decbench", ignore=ignore)
    return dest


def sandbox_argv(run_dir: Path, package: Path) -> list[str]:
    """``bwrap`` prefix exposing only what the agent needs (see module docstring)."""
    home = Path.home()
    binds = [Path(os.path.realpath(sys.executable)).parents[1], Path(sys.prefix)]
    node = shutil.which("node")
    if node:
        binds.append(Path(node).resolve().parents[1])
    argv = ["bwrap", "--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc"]
    argv += ["--tmpfs", "/tmp", "--tmpfs", str(home)]
    for path in binds:
        argv += ["--ro-bind", str(path), str(path)]
    argv += ["--bind", str(run_dir), str(run_dir), "--ro-bind", str(package), str(package)]
    return argv + ["--die-with-parent", "--"]


def codex_options(model: str, effort: str) -> list[str]:
    """Options shared by the first ``codex exec`` and every ``codex exec resume``."""
    argv = [
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
        "-m",
        model,
        "-c",
        f"model_reasoning_effort={effort}",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        'web_search="disabled"',
    ]
    for feature in DISABLED_FEATURES:
        argv += ["--disable", feature]
    return argv


def _run_agent(
    cmd: list[str], cwd: Path, env: dict[str, str], log: Path, seconds: float
) -> str | None:
    """Run one codex invocation until it exits or ``seconds`` pass; returns its thread id."""
    with open(log, "a") as out:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=max(1.0, seconds))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
    thread = None
    for line in log.read_text(errors="replace").splitlines():
        m = re.search(r'"thread_id"\s*:\s*"([0-9a-f-]{36})"', line)
        if m:
            thread = m.group(1)
    return thread


def _workbench(workspace: Path, dataset: Path, workers: int) -> dict[str, Any]:
    from decbench.metrics.fixups.workbench import evaluate, summarize

    return summarize(evaluate(dataset, workspace / "fixup.py", workers))


def _choose_module(ws: Path, workers: int) -> tuple[Path, dict[str, Any]]:
    """The final fixup.py, or the full-eval snapshot with the best byte-match mean if that
    scores higher or the final one breaks."""
    from decbench.metrics import fixups

    candidates: list[tuple[float, int, Path]] = []
    try:
        fixups.load_path(ws / "fixup.py")
        rate = _workbench(ws, ws / "data" / "dev.jsonl.gz", workers)["bytematch_mean"]
        candidates.append((rate, 1, ws / "fixup.py"))
    except Exception as exc:  # noqa: BLE001
        print(f"[run] final fixup.py unusable: {exc!r}", flush=True)
    index = ws / "snapshots" / "index.jsonl"
    if index.is_file():
        rows = [json.loads(line) for line in index.read_text().splitlines() if line.strip()]
        if rows:
            best = max(rows, key=lambda r: r["bytematch_mean"])
            candidates.append((best["bytematch_mean"], 0, ws / "snapshots" / best["file"]))
    if not candidates:
        raise SystemExit("no usable fixup module")
    rate, _final, path = max(candidates)
    return path, {"chosen": path.name, "dev_bytematch_mean": rate}


def cmd_run(args: argparse.Namespace) -> int:
    from decbench.metrics import fixups
    from decbench.metrics.fixups.workbench import evaluate, summarize

    data = Path(args.data).resolve() / args.decompiler
    run_dir = Path(args.runs).resolve() / args.decompiler
    ws = run_dir / "workspace"
    if run_dir.exists() and not args.force:
        raise SystemExit(f"{run_dir} exists; pass --force to start over")
    shutil.rmtree(run_dir, ignore_errors=True)
    (ws / "data").mkdir(parents=True)
    shutil.copy2(data / "dev.jsonl.gz", ws / "data" / "dev.jsonl.gz")
    (ws / "fixup.py").write_text(TEMPLATE.format(decompiler=args.decompiler))
    prompt = PROMPT.read_text().replace("{decompiler}", args.decompiler)
    prompt = prompt.replace("{minutes}", str(args.minutes))
    (ws / "README.md").write_text(prompt[prompt.index("## The workbench") :])
    (run_dir / "prompt.md").write_text(prompt)

    home = run_dir / "codex-home"
    home.mkdir()
    shutil.copy2(Path(args.codex_auth).expanduser(), home / "auth.json")
    os.chmod(home / "auth.json", 0o600)
    package = snapshot_package(run_dir / "pkg")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI_", "CODEX_"))}
    env.update(
        CODEX_HOME=str(home),
        PYTHONPATH=str(package),
        FIXUP_WORKERS=str(args.workers),
        PATH=f"{Path(sys.executable).parent}:{env.get('PATH', '')}",
        PYTHONDONTWRITEBYTECODE="1",
    )

    start = time.time()
    deadline = start + 60 * args.minutes
    (ws / ".deadline").write_text(str(deadline))
    wrap = sandbox_argv(run_dir, package)
    options = codex_options(args.model, args.effort)
    log = run_dir / "codex.jsonl"
    first = [*wrap, "codex", "exec", *options, "-C", str(ws), prompt]
    thread = _run_agent(first, ws, env, log, deadline - time.time())
    sessions = 1
    idle = 0
    while thread and deadline - time.time() > MIN_RESUME_SECONDS and idle < MAX_IDLE_RESUMES:
        before = (ws / "fixup.py").read_bytes()
        message = CONTINUE.format(minutes=int((deadline - time.time()) / 60))
        resume = [*wrap, "codex", "exec", "resume", *options, thread, message]
        _run_agent(resume, ws, env, log, deadline - time.time())
        sessions += 1
        idle = idle + 1 if (ws / "fixup.py").read_bytes() == before else 0
    used = (time.time() - start) / 60

    chosen, choice = _choose_module(ws, args.workers)
    dest = fixups.GENERATED / f"{fixups.module_name(args.decompiler)}.py"
    shutil.copy2(chosen, ws / "chosen_fixup.py")
    dev = summarize(evaluate(ws / "data" / "dev.jsonl.gz", ws / "chosen_fixup.py", args.workers))
    held = summarize(evaluate(data / "heldout.jsonl.gz", ws / "chosen_fixup.py", args.workers))
    report = {
        "decompiler": args.decompiler,
        "model": args.model,
        "effort": args.effort,
        "budget_minutes": args.minutes,
        "used_minutes": round(used, 1),
        "sessions": sessions,
        "date": dt.date.today().isoformat(),
        **choice,
        "dev": dev,
        "heldout": held,
    }
    (run_dir / "report.json").write_text(json.dumps(report, indent=2))
    header = (
        f"# Generated by scripts/fixup_agent.py on {report['date']}: codex {args.model} "
        f"({args.effort}), {args.minutes}-minute budget, {used:.0f} minutes used.\n"
        f"# Compile rate, raw -> fixed: dev {100 * dev['raw_compile_rate']:.1f}% -> "
        f"{100 * dev['compile_rate']:.1f}%, held-out {100 * held['raw_compile_rate']:.1f}% -> "
        f"{100 * held['compile_rate']:.1f}%.\n"
    )
    dest.write_text(header + chosen.read_text())
    notes = ws / "NOTES.md"
    if notes.is_file():
        shutil.copy2(notes, dest.with_suffix(".md"))
    print(json.dumps(report, indent=2))
    return 0


_ALLOWED_PREFIXES = ("/usr/", "/bin/", "/lib", "/etc/", "/dev/", "/tmp/")
_SUSPICIOUS = re.compile(r"\b(?:curl|wget|pip|git|ssh|scp|nc|python[\d.]*\s+-m\s+pip)\b")


def cmd_audit(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    allowed = (str(run_dir), str(REPO / "decbench"), sys.prefix, *_ALLOWED_PREFIXES)
    flagged = 0
    commands = []
    for line in (run_dir / "codex.jsonl").read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        item = event.get("item") or {}
        if event.get("type") != "item.completed" or item.get("type") != "command_execution":
            continue
        cmd = item.get("command", "")
        commands.append(cmd)
        paths = re.findall(r"(?<![\w.])/(?:[\w.+-]+/?)+", cmd)
        outside = [
            p
            for p in paths
            if p.startswith("/proc/") or (not p.startswith(allowed) and os.path.exists(p))
        ]
        if outside or _SUSPICIOUS.search(cmd):
            flagged += 1
            print(f"FLAG {cmd[:300]!r}  outside={outside[:5]}")
    (run_dir / "commands.txt").write_text("\n".join(commands) + "\n")
    print(f"{len(commands)} commands, {flagged} flagged; full list in {run_dir / 'commands.txt'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("dataset", help="export one decompiler's functions, scored raw")
    p.add_argument("results")
    p.add_argument("-d", "--decompiler", required=True)
    p.add_argument("-o", "--out", default="fixup_data")
    p.add_argument("-p", "--project", action="append", default=[], help="limit to these")
    p.add_argument("-j", "--workers", type=int, default=16)
    p = sub.add_parser("run", help="run the fixup agent for one decompiler")
    p.add_argument("-d", "--decompiler", required=True)
    p.add_argument("--data", default="fixup_data")
    p.add_argument("--runs", default="fixup_runs")
    p.add_argument("--minutes", type=int, default=120)
    p.add_argument("--model", default="gpt-5.6-sol")
    p.add_argument("--effort", default="high")
    p.add_argument("-j", "--workers", type=int, default=12)
    p.add_argument("--codex-auth", default="~/.codex/auth.json")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("audit", help="list and flag the commands an agent ran")
    p.add_argument("run_dir")
    args = parser.parse_args()
    return {"dataset": cmd_dataset, "run": cmd_run, "audit": cmd_audit}[args.cmd](args)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    sys.exit(main())
