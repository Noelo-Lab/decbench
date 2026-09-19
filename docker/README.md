# DecBench docker images

This directory is decbench's single Docker home. Four images package
**external-CLI** decompiler backends:

| backend  | spec id  | image tag                | Dockerfile           | native?              |
|----------|----------|--------------------------|----------------------|----------------------|
| RetDec   | `retdec` | `decbench/retdec:latest` | `retdec.Dockerfile`  | no (Docker only)     |
| Reko     | `reko`   | `decbench/reko:latest`   | `reko.Dockerfile`    | no (Docker only)     |
| r2dec    | `r2dec`  | `decbench/r2dec:6.2.0`   | `r2dec.Dockerfile`   | no (Docker only)     |
| Glaurung | `glaurung` | `decbench/glaurung:latest` | `glaurung.Dockerfile` | **yes** |

Unlike the canonical native API backends (angr/ghidra/ida/binja — in-process drivers
of each tool's own API, `decbench/decompilers/raw/`), these ship as standalone
CLIs, so decbench runs them in a container. **RetDec and Reko** emit whole-
program C that decbench splits into per-function snippets; function **names and
addresses** come from the binary's ELF symbol table (pyelftools), so addresses
are in ELF file space and match DWARF — the same convention as the raw
backends. **r2dec** is different: its container driver returns address-keyed
per-function JSON straight from radare2's **own** analysis (`aaa` + `aflj`), so
it needs no symbol table and works on fully stripped binaries.

RetDec and Reko do not expose stack variables or line mappings. r2dec returns
address-keyed variable and line evidence from radare2.

## Building an image

Images are **never auto-built** (building is a multi-minute side effect).
`is_available()` only checks for the configured local image.

```python
DockerizedDecompiler.is_available()  # docker present AND `docker image inspect <image>` ok
```

Build explicitly with the CLI (which calls `DockerizedDecompiler.build_image()`):

```bash
decbench decompiler-build retdec
decbench decompiler-build reko
decbench decompiler-build r2dec
decbench decompiler-build glaurung
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

The backend requires the local `decbench/r2dec:6.2.0` image. It builds the
matching radare2 and r2dec 6.2.0 release tags and verifies `pdd` during the
build; the runtime driver also fails if `pdd` is unavailable.

The in-container driver `r2dec-decompile.py` is invoked as
`/in/<bin> /work/out.json [/work/targets.json]`. `targets.json` (optional) is a
JSON list of ELF-file-space addresses to restrict to (matched Thumb-bit
tolerant); `out.json` is a versioned object whose `functions` field contains
one address-keyed record per function.

### Glaurung

The raw Glaurung backend remains address-scoped rather than whole-program. It
prefers `GLAURUNG_BIN`, DecBench configuration, or `$PATH`, then falls back to
the image. `decompiler-build` resolves `GLAURUNG_REF` to an immutable source
commit, and the image records it at `/opt/glaurung.rev`. At runtime the backend
mounts only the input binary, read-only, disables networking, and captures the
same JSON the native CLI emits. The checked-in default ref is the revision used
for the submitted sample-set evaluation; `GLAURUNG_REF` can select another
revision explicitly. The image contains no credentials.

## Other images (not decompiler backends)

### decbench-compile (`compile.Dockerfile`)

The slim cross-compile image for the cps (ARM) + malware (ARM/PE) targets — the
host has no cross/mingw gcc, so `scripts/compile_all.py` runs inside it for
those projects. Unlike the decompiler images it is built from the **repo root**
context (so `.dockerignore` applies), with the repo bind-mounted at runtime:

```bash
docker build -f docker/compile.Dockerfile -t decbench-compile .
```

See the full-run steps in `docs/benchmarking.md` and the file's own header for
the runtime `docker run` invocation.

### llm-agents (`llm-agents.Dockerfile`)

Container mode for the LLM coding-agent decompilers (`claude-code` / `kimi-code`,
`decbench/decompilers/llm_dec.py`): both agent CLIs plus only the allowed
binary-inspection tools (objdump/readelf/nm/strings/xxd/file). The image is
credential-free — the backend bind-mounts the host's token dirs per call. Built
manually (no `decompiler-build` hook); see `docs/decompilers.md`.

## Files in this directory

- `retdec.Dockerfile`, `reko.Dockerfile`, `r2dec.Dockerfile`,
  `glaurung.Dockerfile` — the decompiler
  backend images.
- `compile.Dockerfile` — the `decbench-compile` cross-compile image (see above).
- `llm-agents.Dockerfile` — the claude-code/kimi-code container mode (see above).
- `reko-decompile.sh` — Reko in-container driver (copied to `/opt/reko/decompile.sh`).
- `r2dec-decompile.py` — r2dec in-container driver (copied to `/opt/`).

## Notes / limitations

- Reko / RetDec CLI flags vary slightly across versions; the helper scripts run
  permissively and gather any `*.c` output. Bump `RETDEC_VERSION`/`REKO_REF` args
  and retag the image to change versions (the dockerized backends do not read
  per-version settings from `decompilers.toml`).
