# LLM / coding-agent decompilers (Codex, Claude Code)

DecBench can benchmark a **general coding agent driven as a decompiler**. For
each target function the agent is handed the (stripped) binary and asked to
reconstruct the original C *by hand* — it is **forbidden from using any
decompiler** and may only use simple disassemblers (`objdump`, `readelf`, `nm`,
`strings`, `xxd`, `file`). Its C output is scored by GED / type_match /
byte_match exactly like Ghidra or IDA.

Two backends ship today (`decbench/decompilers/llm_dec.py`):

| id            | tool            | default model        | credentials |
|---------------|-----------------|----------------------|-------------|
| `codex`       | OpenAI Codex CLI| `gpt-5.6-sol`        | `~/.codex/auth.json` **or** `OPENAI_API_KEY` |
| `claude-code` | Claude Code CLI | `claude-opus-4-8`    | `~/.claude/.credentials.json` **or** `ANTHROPIC_API_KEY` |

Pin a model as a version spec so it becomes its own scoreboard column:
`-d codex@gpt-5.6-sol`, `-d claude-code@claude-opus-4-8`.

## The shared prompt

Every backend uses one common instruction, `LLM_DECOMPILE_PROMPT` in
`decbench/decompilers/llm_dec.py`. It states the goal (reconstruct
original-source-faithful C for one function), the **hard tool policy** (no
decompilers of any kind; simple disassemblers only), the method (read the
assembly, recover types/control-flow/variables, prefer idiomatic structured C),
and a **file-based output contract** (write only the C for the one function to
`decompiled.c`). Per-function specifics — binary path, entry address,
architecture, a short linear-disassembly hint, the output filename — are appended
per call. Edit the constant to change the policy for both backends at once.

## Cost control — run ONLY on the sample-set

One agentic CLI call per function is expensive, so these backends are meant to
run on the **`sample-set` slice (~250 functions)** and nothing else. There are
two independent guards:

1. **The run gate (primary).** Freeze the sample-set to a manifest, then point
   the driver at it. The driver restricts every binary's decompile target set to
   the listed function names and *skips binaries with none*, so off-slice
   functions never reach the agent:

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

`DECBENCH_SAMPLESET_MANIFEST` gates the *whole run* (all decompilers in it), so
run the LLM backends in their own invocation rather than mixing them with a
normal ghidra/ida pass.

## Config knobs (`~/.config/decbench/decompilers.toml`)

```toml
[codex.versions.default]
model = "gpt-5.6-sol"  # the gpt-5.6 variant a ChatGPT-account login allows
# timeout = 900        # per-function agent wall-clock budget (seconds)
# max_funcs = 8        # per-binary hard cap (runaway guard)
# docker_image = "decbench/llm-agents:latest"   # run in a container (below)

[claude-code.versions.default]
model = "claude-opus-4-8"
```

Env equivalents: `DECBENCH_LLM_MODEL`, `DECBENCH_LLM_TIMEOUT`,
`DECBENCH_LLM_MAX_FUNCS`, `DECBENCH_LLM_DOCKER_IMAGE`. Per-decompiler wall-clock
in the driver: `DECBENCH_CODEX_TIMEOUT` / `DECBENCH_CLAUDE_CODE_TIMEOUT`
(default 3600s per binary).

## Running in the project container (token inheritance)

By default the backends run the CLI **on the host**, which already holds the
login — the subprocess just inherits `~/.codex` / `~/.claude` and the key env
vars. To run the CLI **inside a container** instead (so the whole toolchain is
pinned), build the agent image and set `docker_image`:

```bash
docker build -f docker/llm-agents.Dockerfile -t decbench/llm-agents:latest docker/

DECBENCH_LLM_DOCKER_IMAGE=decbench/llm-agents:latest \
  DECBENCH_DECOMPILERS=codex \
  DECBENCH_SAMPLESET_MANIFEST=results/full_run/sample_set_manifest.json \
  python scripts/run_benchmark.py results/full_run
```

The image carries the CLIs and the permitted inspection tools but **no
credentials**. Per agent call the backend runs:

```
docker run --rm -v <workdir>:/work -w /work \
  -v ~/.codex:/root/.codex:ro -v ~/.claude:/root/.claude:ro \
  -e ANTHROPIC_API_KEY -e OPENAI_API_KEY -e CODEX_HOME=/root/.codex -e HOME=/root \
  decbench/llm-agents:latest <codex exec ... | claude -p ...>
```

so the container inherits the host's token from outside — the secret is
bind-mounted read-only and forwarded via env, never baked into the image.

## How it fits the pipeline

The driver strips each binary and passes DWARF `low_pc` addresses (the agent
sees no symbols — the honest RE setting, identical to what Ghidra/IDA get). The
backend labels each function `sub_<addr>`; `run_benchmark._relabel_to_dwarf`
renames the placeholder to the real symbol for name-based evaluation. Missing
line-maps and variables are fine — GED parses the C directly and type_match
falls back to text parsing. After a first run, refresh the metric overlays
(`scripts/reeval_*`) and `scripts/rebuild_function_data.py` before publishing, as
with any newly added decompiler.
