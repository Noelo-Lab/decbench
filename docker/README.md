# DecBench dockerized decompilers

This directory holds the Docker images and helper scripts for the **external,
non-declib** decompiler backends in `decbench/decompilers/dockerized.py`:

| backend  | spec id  | image tag                | Dockerfile           | native?              |
|----------|----------|--------------------------|----------------------|----------------------|
| RetDec   | `retdec` | `decbench/retdec:latest` | `retdec.Dockerfile`  | no (Docker only)     |
| Reko     | `reko`   | `decbench/reko:latest`   | `reko.Dockerfile`    | no (Docker only)     |
| r2dec    | `r2dec`  | `decbench/r2dec:latest`  | `r2dec.Dockerfile`   | **yes** (radare2)    |

Unlike the declib-backed decompilers (angr/ghidra/ida/binja), these ship as
standalone CLIs, so decbench runs them in a container, captures their whole-
program C output, and splits it into per-function snippets. Function **names and
addresses** come from the binary's ELF symbol table (pyelftools), so addresses
are in ELF file space and match DWARF — exactly like the declib backends.

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

or equivalently with `docker build` (build context = this `docker/` directory,
since the helper scripts live here):

```bash
docker build -f docker/retdec.Dockerfile -t decbench/retdec:latest docker/
docker build -f docker/reko.Dockerfile   -t decbench/reko:latest   docker/
docker build -f docker/r2dec.Dockerfile  -t decbench/r2dec:latest  docker/
```

`build_image()` runs `docker build -f docker/<dockerfile> -t <image> <docker/>`
and returns the `docker build` exit code.

## How each backend is invoked

decbench's `DockerizedDecompiler._run_docker` mounts the binary **read-only** at
`/in/<name>` and a host temp dir read-write at `/work`, then runs the image:

### RetDec

```bash
docker run --rm -v /path/bin:/in/bin:ro -v /tmp/out:/work \
    decbench/retdec:latest /in/bin -o /work/out.c
```

The image's `ENTRYPOINT` is `retdec-decompiler`; it writes `/work/out.c`, which
decbench reads back as whole-program C. Built from the pinned RetDec **v5.0**
Linux release tarball (`avast/retdec`), so the build is fast and reproducible.

### Reko

```bash
docker run --rm -v /path/bin:/in/bin:ro -v /tmp/out:/work \
    decbench/reko:latest /in/bin /work/out.c
```

The image ships `/opt/reko/decompile.sh` (`reko-decompile.sh` in this dir),
which runs Reko's headless CmdLine driver and concatenates every emitted `*.c`
into `/work/out.c`. Reko is built from source with the **.NET 8 SDK** (multi-stage
build → `mcr.microsoft.com/dotnet/runtime:8.0` runtime). Heavy build (clones +
`dotnet publish`).

### r2dec (native-first)

r2dec prefers a **native** run: radare2 + `r2pipe` are used directly on the host
(no container) via `pd:d`/`pdd` (the real r2dec plugin) or radare2's built-in
`pdc` pseudo-decompiler as a fallback. `is_available()` is true if **either**
native radare2+r2pipe is present **or** the Docker image exists.

The Docker fallback builds radare2 **from source** (so the dev headers exist and
`r2pm -ci r2dec` can compile the plugin — the host's packaged radare2 lacks
`/usr/include/libr`, which is exactly why the plugin can't build natively here).
The in-container driver `r2dec-decompile.py` writes whole-program C to
`/work/out.c`, wrapping each function in a synthetic `name(void){…}` definition
so decbench can split it by symbol.

```bash
# only used when native r2dec/r2pipe is unavailable
docker run --rm -v /path/bin:/in/bin:ro -v /tmp/out:/work \
    decbench/r2dec:latest /in/bin /work/out.c
```

## Files in this directory

- `retdec.Dockerfile`, `reko.Dockerfile`, `r2dec.Dockerfile` — the images.
- `reko-decompile.sh` — Reko in-container driver (copied to `/opt/reko/decompile.sh`).
- `r2dec-decompile.py` — r2dec in-container driver (copied to `/opt/`).

## Notes / limitations

- On the dev machine, the native r2dec plugin **cannot** build (no radare2 dev
  headers, no sudo), so the native path uses the built-in `pdc` pseudo-decompiler.
  The Docker image builds radare2 from source to get the real r2dec plugin.
- Reko / RetDec CLI flags vary slightly across versions; the helper scripts run
  permissively and gather any `*.c` output. Bump `RETDEC_VERSION`/`REKO_REF` args
  to change versions (and add a `[retdec.versions."X"]` / image-tag mapping in
  `~/.config/decbench/decompilers.toml` for versioned runs).
