# Glaurung backends (`glaurung`, `glaurung-agentic`)

Two backends for [Glaurung](https://github.com/mjbommar/glaurung), an AI-native
reverse-engineering framework. Both live in
`decbench/decompilers/raw/glaurung_raw.py` and `…/glaurung_agentic.py`.

**Glaurung is a from-scratch native decompiler, not a wrapper.** Its decompiler
is a multi-pass Rust LLIR pipeline — CFG discovery → semantic lift
(`lift_x86`/`lift_arm64`) → SSA → control-flow structuring → AST lowering →
expression reconstruction → DCE → ABI arg / name / type recovery → C render. It
does **not** call Ghidra/RetDec/angr (contrast `kuna`, a Ghidra-decompiler port,
and the declib backends). The only external pieces are commodity instruction
*decoders* (iced-x86, capstone) and format parsers (object/goblin) — the
disassembly primitive every decompiler builds on.

## `glaurung` — native decompiler

Shells out to the Glaurung CLI in parseable-C mode and parses JSON:

```
glaurung decompile <binary> --vas <va,va,…> --style decbench --format json   # target-scoped
glaurung decompile <binary> --all --limit <N> --style decbench --format json # whole-binary fallback
```

`--style decbench` emits a valid C translation-unit fragment per function — a
real signature with declared locals — so DecBench's Joern-based GED and the
C-signature type_match parser consume it directly. Parameters and return values
carry their **recovered machine width** (`int fn(int arg0, …)`, not a blanket
`long`), and the body states the widening the hardware performed, so a 32-bit
value read into a 64-bit register is spelled `(unsigned long)(unsigned int)x`
rather than silently changing the arithmetic.
Entry VAs are already ELF-file-space (like ida/binja/kuna on non-PIE ELFs), so
they are used as the DecBench `address` **without `elf_min_vaddr` rebasing**.

Config (env):

| var | meaning |
|-----|---------|
| `GLAURUNG_BIN` | explicit CLI path; invalid explicit paths fail closed |
| `GLAURUNG_IMAGE` | raw fallback image (default `decbench/glaurung:latest`) |
| `GLAURUNG_REPO` | source repository used by `decompiler-build` |
| `GLAURUNG_REF` | source branch, tag, or SHA used by `decompiler-build` |
| `GLAURUNG_VERSION` | native version label outside a Git checkout |
| `DECBENCH_GLAURUNG_TIMEOUT` | per-binary wall-clock seconds (else `binary_timeout_seconds`) |
| `DECBENCH_GLAURUNG_TIMEOUT_MS` | per-function analysis budget (ms) |
| `DECBENCH_GLAURUNG_LIMIT` | `--all` fallback function cap (default 30000) |

## `glaurung-agentic` — native decompile + LLM enrichment

A **different category** from `codex`/`claude-code` (which forbid decompilers and
reconstruct C by hand). This runs Glaurung's *own* decompiler and then its LLM
re-render pass, via `glaurung explain <binary> --func <va> --format json`
(native pseudocode → infer signature → classify role → rewrite idiomatic C).
One agent call per function, so the same guards as the LLM backends apply:

- **Sample-set gate (primary):** the run driver restricts each binary's target
  set (`DECBENCH_SAMPLESET_MANIFEST`); off-slice functions never reach the agent.
- **Per-binary cap (backstop):** `max_funcs` (default 8, `DECBENCH_GLAURUNG_MAX_FUNCS`).

Model is a **version spec** — pin it so it becomes its own scoreboard column:

```
decbench evaluate <bin> -s <src> -d glaurung-agentic@openai:gpt-5.4-mini
```

which is forwarded to `explain` via `GLAURUNG_LLM_MODEL`. Requires `OPENAI_API_KEY`
(default openai model) or `ANTHROPIC_API_KEY` (fallback / an `anthropic:*` spec)
in the environment. Config: `DECBENCH_GLAURUNG_FN_WORKERS` (concurrency),
`DECBENCH_GLAURUNG_LLM_TIMEOUT` (per-function seconds),
`DECBENCH_GLAURUNG_LLM_STAGE_TIMEOUT_MS` (per-stage budget, default 120000),
and `DECBENCH_GLAURUNG_SAVE_TRACES`.

Every invocation passes `--require-llm`. The backend accepts output only when
the signature and idiomatic-rewrite stages each report `source = llm`. Role
classification may report `heuristic` because that stage intentionally skips
an API call when its deterministic classifier is already at least 0.70
confident; errors and API fallbacks still fail closed rather than silently
entering the agentic result column.

## Installing the Glaurung CLI

The reproducible benchmark installation needs Docker only:

```bash
decbench decompiler-build glaurung
decbench list-decompilers
decbench run projects/sailr/bzip2.toml -O O0 -d glaurung
```

`decompiler-build` resolves `GLAURUNG_REF` to an immutable SHA before building
`docker/glaurung.Dockerfile`. The multi-stage image compiles Glaurung's Rust
extension from that checkout using its committed `uv.lock`, copies only the
runtime environment into the final image, and records the source revision at
`/opt/glaurung.rev`. A raw run mounts the target binary read-only, disables
container networking, and does not forward API credentials.

Developers may instead use a native Glaurung working tree. Glaurung is a
maturin project exposing a `glaurung` console script backed by a native Rust
extension:

```bash
git clone https://github.com/mjbommar/glaurung
cd glaurung
uv sync --locked --no-dev
export GLAURUNG_BIN="$(command -v glaurung)"
```

Selection is native first and container second. Set `GLAURUNG_BIN` explicitly
when benchmarking a working tree; its value wins outright, including when it
is invalid, so a typo cannot silently benchmark a stale image.

The container is deliberately raw-only. `glaurung-agentic` runs externally
with the contributor's API credentials against DecBench's frozen 250-function
sample kit; credentials are never built into or forwarded to the raw image.

## Scope / limitations (v1)

- **Architecture:** the LLIR lifter supports **x86-64, AArch64, and ARM32/Thumb-2**
  (ARMv7). The DecBench CPS firmware is Cortex-M Thumb, so the ARM slice is
  covered. ARM32 mode selection uses ELF mapping symbols, function-symbol Thumb
  bits, and bounded decode probes; dedicated round-trip lanes cover both Thumb-2
  and A32.
- **Structured variables:** not emitted yet. type_match uses its C-signature
  text-parsing path over the emitted prototype; line-mappings are omitted (GED
  parses the C directly). Scalar widths and pointer-ness are recovered; struct
  and array types are not, so an aggregate parameter still appears as a pointer
  to its element type.
- The decompiler's control-flow structuring and type recovery are still
  maturing, so raw structural/type fidelity trails mature engines like Ghidra.
