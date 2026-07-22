# DecBench docker images

This directory is decbench's single Docker home. Three images are the
**external-CLI** decompiler backends in `decbench/decompilers/dockerized.py`:

| backend  | spec id  | image tag                | Dockerfile           | native?              |
|----------|----------|--------------------------|----------------------|----------------------|
| RetDec   | `retdec` | `decbench/retdec:latest` | `retdec.Dockerfile`  | no (Docker only)     |
| Reko     | `reko`   | `decbench/reko:latest`   | `reko.Dockerfile`    | no (Docker only)     |
| r2dec    | `r2dec`  | `decbench/r2dec:latest`  | `r2dec.Dockerfile`   | **yes** (radare2)    |

Unlike the canonical raw backends (angr/ghidra/ida/binja — declib-free drivers
of each tool's own API, `decbench/decompilers/raw/`), these ship as standalone
CLIs, so decbench runs them in a container. **RetDec and Reko** emit whole-
program C that decbench splits into per-function snippets; function **names and
addresses** come from the binary's ELF symbol table (pyelftools), so addresses
are in ELF file space and match DWARF — the same convention as the raw
backends. **r2dec** is different: its container driver returns address-keyed
per-function JSON straight from radare2's **own** analysis (`aaa` + `aflj`), so
it needs no symbol table and works on fully stripped binaries.

These tools do not expose stack variables / line mappings uniformly, so the
`FunctionDecompilation.variables` and `.line_mappings` lists are empty. The
metrics degrade gracefully: GED still parses the recovered C, byte_match
recompiles it, and type_match falls back to regex/name matching.

## Building an image

Images are **never auto-built** (building is a multi-minute side effect).
`is_available()` only checks whether the image already exists locally:

```python
DockerizedDecompiler.is_available()  # docker present AND `docker image inspect <image>` ok
```

Build explicitly with the CLI (which calls `DockerizedDecompiler.build_image()`):

```bash
decbench decompiler-build retdec
decbench decompiler-build reko
decbench decompiler-build r2dec
```

`build_image()` runs `docker build -f docker/<dockerfile> -t <image> docker/`
(build context = this `docker/` directory, since the helper scripts live here)
and returns the `docker build` exit code. Each Dockerfile's header shows its
own equivalent `docker build` command.

## How each backend is invoked

decbench's `DockerizedDecompiler._run_docker` mounts the binary **read-only** at
`/in/<name>` and a host temp dir read-write at `/work`, then runs the image:

### RetDec

The image's `ENTRYPOINT` is `retdec-decompiler`, invoked as
`/in/<bin> -o /work/out.c`; decbench reads `/work/out.c` back as whole-program
C. Built from the pinned RetDec **v5.0** Linux release tarball (`avast/retdec`),
so the build is fast and reproducible.

### Reko

The image ships `/opt/reko/decompile.sh` (`reko-decompile.sh` in this dir),
invoked as `/in/<bin> /work/out.c`; it runs Reko's headless CmdLine driver and
concatenates every emitted `*.c` into `/work/out.c`. Reko is built from source
with the **.NET 8 SDK** (multi-stage build →
`mcr.microsoft.com/dotnet/runtime:8.0` runtime). Heavy build (clones +
`dotnet publish`).

### r2dec

Selection order (`R2DecDecompiler._select_path`): **native with the r2dec
plugin** (real `pdd`, no container overhead) > **this Docker image** > native
`pdc` (radare2's built-in pseudo-decompiler, whose asm-like output rarely
parses for GED). On hosts whose packaged radare2 lacks the dev headers to
build the plugin (`r2pm -ci r2dec` needs `/usr/include/libr`), the image **is**
the benchmark path: it builds radare2 **from source** so the real r2dec plugin
compiles. `is_available()` is true if **either** native radare2+r2pipe is
present **or** the Docker image exists.

The in-container driver `r2dec-decompile.py` is invoked as
`/in/<bin> /work/out.json [/work/targets.json]`. `targets.json` (optional) is a
JSON list of ELF-file-space addresses to restrict to (matched Thumb-bit
tolerant); `out.json` is a JSON list of `{"addr", "baddr", "name", "code"}`
entries — one per function, keyed by radare2's own analysis addresses, so
nothing is split by symbol.

## Other images (not decompiler backends)

### decbench-compile (`compile.Dockerfile`)

The slim cross-compile image for the cps (ARM) + malware (ARM/PE) targets — the
host has no cross/mingw gcc, so `scripts/compile_all.py` runs inside it for
those projects. Unlike the decompiler images it is built from the **repo root**
context (so `.dockerignore` applies), with the repo bind-mounted at runtime:

```bash
docker build -f docker/compile.Dockerfile -t decbench-compile .
```

See the full-run steps in the top-level CLAUDE.md and the file's own header for
the runtime `docker run` invocation.

### llm-agents (`llm-agents.Dockerfile`)

Container mode for the LLM coding-agent decompilers (`codex` / `claude-code`,
`decbench/decompilers/llm_dec.py`): both agent CLIs plus only the allowed
binary-inspection tools (objdump/readelf/nm/strings/xxd/file). The image is
credential-free — the backend bind-mounts the host's token dirs per call. Built
manually (no `decompiler-build` hook); see `docs/LLM_DECOMPILERS.md`.

## Files in this directory

- `retdec.Dockerfile`, `reko.Dockerfile`, `r2dec.Dockerfile` — the decompiler
  backend images.
- `compile.Dockerfile` — the `decbench-compile` cross-compile image (see above).
- `llm-agents.Dockerfile` — the codex/claude-code container mode (see above).
- `reko-decompile.sh` — Reko in-container driver (copied to `/opt/reko/decompile.sh`).
- `r2dec-decompile.py` — r2dec in-container driver (copied to `/opt/`).

## Notes / limitations

- On the dev machine, the native r2dec plugin **cannot** build (no radare2 dev
  headers, no sudo), so `_select_path` lands on the Docker image — there the
  image, not native `pdc`, is the benchmark path.
- Reko / RetDec CLI flags vary slightly across versions; the helper scripts run
  permissively and gather any `*.c` output. Bump `RETDEC_VERSION`/`REKO_REF` args
  and retag the image to change versions (the dockerized backends do not read
  per-version settings from `decompilers.toml`).
