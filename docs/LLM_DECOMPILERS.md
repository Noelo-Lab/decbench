# LLM / coding-agent decompilers (Codex, Claude Code)

DecBench can benchmark a **general coding agent driven as a decompiler**. For
each target function the agent is handed the (stripped) binary and asked to
reconstruct the original C *by hand* — it is **forbidden from using any
decompiler** and may only use simple disassemblers (`objdump`, `readelf`, `nm`,
`strings`, `xxd`/`od`, `file`, `size`, `c++filt` — `LLM_DECOMPILE_PROMPT` has
the exact list). Its C output is scored by GED / type_match / byte_match exactly
like Ghidra or IDA.

Two backends ship today (`decbench/decompilers/llm_dec.py`):

| id            | tool            | default model        | credentials |
|---------------|-----------------|----------------------|-------------|
| `codex`       | OpenAI Codex CLI| `gpt-5.6-sol`        | `~/.codex/auth.json` **or** `OPENAI_API_KEY` |
| `claude-code` | Claude Code CLI | `claude-opus-4-8`    | `~/.claude/.credentials.json` **or** `ANTHROPIC_API_KEY` |

Pin a model as a version spec so it becomes its own scoreboard column:
`-d codex@gpt-5.6-sol`, `-d claude-code@claude-opus-4-8`.

## The shared prompt

Both backends share one instruction, `LLM_DECOMPILE_PROMPT` in
`decbench/decompilers/llm_dec.py`: reconstruct original-source-faithful C for
one function under the **hard tool policy** above, and write only that
function's C to `decompiled.c`. Per-function specifics (binary path, entry
address, architecture, a short disassembly hint, the output filename) are
appended per call; edit the constant to change the policy for both backends at
once.

## Cost control — run ONLY on the sample-set

One agentic CLI call per function is expensive, so these backends are meant to
run on the **`sample-set` slice (~250 functions)** and nothing else. There are
two independent guards:

1. **The run gate (primary).** Freeze the sample-set to a manifest, then point
   the driver at it. The driver restricts every binary's decompile target set to
   the listed function names and *skips binaries with none*, so off-slice
   functions never reach the agent. The manifest gates the *whole run* (every
   decompiler in it), so give the LLM backends their own invocation rather than
   mixing them into a normal ghidra/ida pass:

   ```bash
   # 1. Freeze the sample-set (seed 1337) from an existing full run.
   python scripts/export_sample_set.py results/full_run
   #    -> results/full_run/sample_set_manifest.json  (250 functions)

   # 2. Additively run the LLM backends, gated to that slice. Every other
   #    project/decompiler resumes from its checkpoint untouched.
   DECBENCH_DECOMPILERS=codex,claude-code \
     DECBENCH_SAMPLESET_MANIFEST=results/full_run/sample_set_manifest.json \
     DECBENCH_WORKERS=24 \
     python scripts/run_benchmark.py results/full_run
   ```

2. **The per-binary cap (backstop).** Even un-gated, each backend refuses to
   issue more than `max_funcs` (default **8**) agent calls for one binary and
   logs a warning. So a forgotten gate degrades to "a few calls per binary",
   never a full-corpus fan-out.

## Config knobs (`~/.config/decbench/decompilers.toml`)

```toml
[codex.versions.default]
model = "gpt-5.6-sol"  # the gpt-5.6 variant a ChatGPT-account login allows
# timeout = 900        # per-function agent wall-clock budget (seconds)
# max_funcs = 8        # per-binary hard cap (runaway guard)
# fn_workers = 4       # decompile this many of a binary's functions concurrently
# docker_image = "decbench/llm-agents:latest"   # run in a container (below)

[claude-code.versions.default]
model = "claude-opus-4-8"
```

Env equivalents: `DECBENCH_LLM_MODEL`, `DECBENCH_LLM_TIMEOUT`,
`DECBENCH_LLM_MAX_FUNCS`, `DECBENCH_LLM_FN_WORKERS`,
`DECBENCH_LLM_DOCKER_IMAGE`. Per-decompiler wall-clock in the driver:
`DECBENCH_CODEX_TIMEOUT` / `DECBENCH_CLAUDE_CODE_TIMEOUT` (default 3600s per
binary).

**Traces.** Every agent call is traced by default (disable with
`DECBENCH_LLM_SAVE_TRACES=0` / `save_traces = false`): the prompt, transcript,
and reconstructed C are written as markdown to `<output_dir>/traces/`, plus the
CLI's own session JSONL — every objdump/tool call, the audit record for the
no-decompilers policy. Set `DECBENCH_LLM_TRACE_DIR` (or `trace_dir`) to collect
all traces under one directory instead.

## Host mode: isolated homes, synced credentials

By default the backends run the CLI **on the host**, but under a
**decbench-owned isolated home** rather than your live config:

- **codex** runs with `CODEX_HOME` pointed at `~/.cache/decbench/codex-home`
  (override: `DECBENCH_CODEX_HOME` / `codex_home`), whose `skills/` dir is kept
  **empty** so the `decompiler` skill (which drives real decompilers) cannot
  load; `auth.json` + `config.toml` are synced from `~/.codex` only when the
  host copy is newer, so codex's own in-place token refresh isn't clobbered.
- **claude-code** strips `CLAUDE_CODE_*`/`CLAUDECODE`/`CLAUDE_PID` from the env
  (a nested `claude` launched from inside a Claude Code session would otherwise
  reattach to the parent's daemon and hang), points `CLAUDE_CONFIG_DIR` at
  `~/.cache/decbench/claude-config` (override: `DECBENCH_CLAUDE_CONFIG_DIR` /
  `claude_config_dir`), and atomically **re-syncs `.credentials.json` from
  `~/.claude` on every call** — the OAuth refresh token rotates, so a one-time
  copy goes stale. When those OAuth credentials exist, `ANTHROPIC_API_KEY` is
  dropped (a set key shadows the much faster OAuth login); force the API-key
  path with `DECBENCH_CLAUDE_USE_API_KEY=1`.

## Running in the project container (token inheritance)

To run the CLI **inside a container** instead (so the whole toolchain is
pinned), build the agent image and set `docker_image`:

```bash
docker build -f docker/llm-agents.Dockerfile -t decbench/llm-agents:latest docker/

DECBENCH_LLM_DOCKER_IMAGE=decbench/llm-agents:latest \
  DECBENCH_DECOMPILERS=codex \
  DECBENCH_SAMPLESET_MANIFEST=results/full_run/sample_set_manifest.json \
  python scripts/run_benchmark.py results/full_run
```

The image carries the CLIs and the permitted inspection tools but **no
credentials** — the host's token dirs are bind-mounted read-only and the key
env vars forwarded per call, so the container "inherits the token from
outside" (the `docker/llm-agents.Dockerfile` header shows the same invocation):

```
docker run --rm -v <workdir>:/work -w /work \
  -v ~/.codex:/root/.codex:ro -v ~/.claude:/root/.claude:ro \
  -e ANTHROPIC_API_KEY -e OPENAI_API_KEY -e CODEX_HOME=/root/.codex -e HOME=/root \
  decbench/llm-agents:latest <codex exec ... | claude -p ...>
```

## How it fits the pipeline

The driver strips each binary and passes DWARF `low_pc` addresses (the agent
sees no symbols — the honest RE setting, identical to what Ghidra/IDA get); the
backend also hands the agent an anonymized `target.bin` copy, so the filename
(`grep`, `nuttx`, …) can't tip an LLM off to recall the source from memory. The
backend labels each function `sub_<addr>`; `run_benchmark._relabel_to_dwarf`
renames the placeholder to the real symbol for name-based evaluation. Missing
line-maps and variables are fine — GED parses the C directly, and type_match
parses the C signature into ABI-positioned arguments plus locals and scores
them through the structured matcher (name-based text parsing only as a last
resort). Before publishing, refresh the metric overlays as with any newly added
decompiler — but note `scripts/reeval_ged.py` and `scripts/reeval_bytematch.py`
hard-code a `DECOMPILERS` tuple that does **not** include `codex`/`claude-code`:
extend those tuples (and run `scripts/reeval_typematch.py`, which covers every
decompiler in the checkpoints) so the overlays cover the LLM columns, then
`scripts/rebuild_function_data.py`.
