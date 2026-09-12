# MSVC / Windows-binary support (experimental)

Status: **prototype** — a working compile container + smoke test, no pipeline
integration yet. This documents what works today, what each metric needs, and
the integration plan.

DecBench's PE story so far is MinGW-only: the malware targets
(`projects/malware/`) are C sources cross-compiled with `gcc-mingw-w64`, which
emits **DWARF** into the PE — so the whole DWARF-based ground-truth stack
(`decbench/utils/binfmt.py`) works unchanged. Real-world Windows software is
built with **MSVC**, which emits **PDB/CodeView, never DWARF** — a different
ground-truth universe. This prototype answers: can we build with *real* MSVC
(`cl.exe`) on the Linux benchmark host, and what would metric coverage look
like?

## What works today

### Compiling with real cl.exe in Docker (`docker/msvc.Dockerfile`)

The `decbench-msvc` image uses [msvc-wine](https://github.com/mstorsjo/msvc-wine):
`vsdownload.py` downloads the MSVC Build Tools + Windows SDK from Microsoft's
official servers (the same manifests the Visual Studio installer uses) and
`install.sh` wraps `cl`/`link`/`lib`/`nmake`/`rc`/... as Unix scripts running
the real Windows tools under Wine. x86 + x64 target architectures are
installed.

```bash
docker build -f docker/msvc.Dockerfile -t decbench-msvc .   # multi-GB download
docker run --rm -v "$PWD":/workspace -w /workspace -e HOME=/tmp \
  --user "$(id -u):$(id -g)" decbench-msvc \
  python3 scripts/msvc_compile_smoke.py /workspace/msvc_smoke_out
```

The smoke test builds **zlib 1.3.1** with its own `win32/Makefile.msc` via
`nmake` in two variants — the Makefile default (`-O2 -Oy- -Zi`, PDB via
`link -debug`) and a `-Od -Zi` override — and verifies: x86-64 PEs are
produced (`zlib1.dll`, `example.exe`, `minigzip.exe`), PDBs exist, **no**
`.debug_*` sections exist, `llvm-pdbutil` can read functions/locals/types from
the PDB, and `cl -P` emits preprocessed sources.

**Verified 2026-07-23** on the benchmark host: image builds in ~15 min
(2.5 GB download from Microsoft's servers, 6.62 GB image; MSVC 19.51.36252
/ toolset 14.51.36231, Windows 11 SDK 10.0.26100.16), both zlib variants
compile and link in seconds, and the smoke test passes end to end.

Wine gotcha (handled by the smoke script): wine refuses a `$HOME` the
invoking uid does not own (e.g. `-e HOME=/tmp` with `--user`), and msvc-wine's
fifo-based wrappers then **hang** instead of failing — the script
self-provisions a wine-safe HOME, so don't pass one.

### Licensing

`vsdownload.py --accept-license` accepts the Visual Studio license
non-interactively (msvc-wine's maintainer documents this tradeoff; the same
manifests drive Microsoft's own installer). The installed toolchain is **not
redistributable**: build the image locally, never push it to a registry. This
mirrors how the IDA/Binary Ninja backends already depend on local,
non-redistributable installs.

### Decompiling MSVC PEs

Needs nothing new: the raw backends + executor already discover and load PE
(ghidra/ida/binja/angr all decompile the MinGW malware PEs today). An MSVC PE
is just another PE to them.

## What the metrics need (the real gap: DWARF vs PDB)

Every piece of decbench ground truth is DWARF-based today
(`decbench/utils/binfmt.py`):

| consumer | DWARF use today | MSVC-PE status |
|---|---|---|
| run driver function filter | `decl_file` (`project_source_functions`) | **missing** — needs PDB function names + module (compiland) provenance |
| `type_match` | variable DIEs (name/type/location) | **missing** — needs a PDB variable reader (does not exist) |
| `byte_match` recompile flags | `DW_AT_producer` flags | **must abstain** — no producer; recompiling with MinGW would not be "the same way" |
| `byte_match` function bytes | DWARF `low_pc`/`high_pc` ranges | **missing** — needs PDB proc address + length |
| GED source side | `.i` preprocessed sources + function identity | **available** — `cl -P` emits preprocessed TUs; names from the PDB |

Verified host-side on the smoke `zlib1.dll`: `binfmt.detect` is
debug-format-agnostic (PE header parse) and returns
`BinInfo(fmt='pe', arch='x86-64', bits=64)`; `dwarf_info` returns `None` and
`producer_flags` returns `[]` (no `.debug_*` sections). Caution:
`recompiler_for` still answers `x86_64-w64-mingw32-gcc` for any x86-64 PE — on
a host with MinGW installed byte_match would silently recompile an MSVC PE the
*wrong* way, which is why integration must add the explicit abstention below.

### What a PDB gives us (verified with llvm-pdbutil on the smoke PDBs)

`/Zi` + `link -debug` PDBs for zlib1.dll: 183 functions (O2) / 201 (Od)
including CRT, 196 struct type records, and per-proc locals (O2: 770
`S_LOCAL`; Od: 826 `S_REGREL32`-style frame-relative records). Concretely for
`adler32`: `S_GPROC32 [..] 'adler32', addr = 0001:0000, code size = 44, type =
'0x1003 (unsigned long (unsigned long, co...)'`.

* **Function names + addresses + code sizes**: `S_GPROC32`/`S_LPROC32` records
  carry the name, `section:offset` address (→ RVA via section headers) and
  code length — enough for the run driver's function filter, for
  function-byte extraction, and for keying decompiled functions.
* **Locals + parameters with types**: `S_LOCAL` (+ `S_DEFRANGE_*` locations)
  and `S_REGREL32` records under each proc carry variable names + type indices
  + param flags; the TPI stream resolves type indices to full records
  (`LF_STRUCTURE`, ...). This is the type_match ground-truth equivalent.
* **Compiland provenance**: module records name each object file (e.g.
  ``Mod 0000 | `Z:\...\adler32.obj```) with per-module source-file lists — the
  `decl_file` equivalent for filtering out CRT/SDK functions.

So a `pdb_info()` sibling to `dwarf_info()` is *feasible*; nothing about the
metrics' logic changes, only the ground-truth reader.

### Metric coverage summary for MSVC PEs

* **GED**: workable now-ish — source CFGs come from preprocessed sources
  (`cl -P` verified working: 144 KB `adler32.i`, the `.i`-equivalent path the
  pipeline already uses) and function identity from the PDB. No Joern/pyjoern
  change needed (still parsing C).
* **type_match**: needs a new PDB ground-truth module (CodeView symbol +
  TPI type reader; `llvm-pdbutil` output or a python PDB parser). Medium
  effort, well-scoped.
* **byte_match**: **abstains** (non-scoring, exactly like ARM-on-host today —
  the Union summary column already treats abstention as "not measurable", not
  a failure). Honest alternative later: recompile with the *containerized*
  cl.exe at matching `/O` flags — but flag recovery without `DW_AT_producer`
  is heuristic, so abstention is the fair default.

This is the same degraded-but-honest posture the cps/ARM targets already have
(GED + type_match carry them, byte_match abstains).

## Integration plan (follow-up, not in this branch)

1. **`MSVCCompiler`** subclass of `decbench/compilers/base.py`: drives
   `nmake`/`cl` via the `decbench-msvc` image (like cps/malware compile inside
   `decbench-compile`), injects `/Zi` + the `/O` flag for the opt level
   (`opt_gcc_flags()` needs an MSVC mapping: `O0→/Od`, `O2→/O2`), collects
   `*.dll`/`*.exe` **and their `.pdb`s** plus `cl -P` preprocessed sources.
2. **Project TOML** `projects/windows/zlib-msvc.toml` (new `windows/` family;
   `gather_tomls()` in the run drivers would need to include it), labels
   `["windows", "msvc"]`.
3. **PDB ground-truth module** (`decbench/utils/pdbinfo.py`): functions
   (name/RVA/length/compiland) + per-function variables (name/type/location),
   used by the run driver's function filter, type_match, and byte_match's
   function-byte extraction. Ship `llvm-pdbutil` on the host or vendor a
   python CodeView parser.
4. **byte_match**: explicit abstention for PE-without-DWARF. This is REQUIRED,
   not optional: `recompiler_for` answers MinGW for any x86-64 PE, so on a
   host with MinGW installed byte_match would recompile an MSVC PE the wrong
   way (it only abstains today because the benchmark host lacks MinGW).
5. Opt-level story: MSVC has no `-fno-inline` equivalent flag spelled the same
   way; `O2-noinline` maps to `/O2 /Ob0`.

## Known limitations / gotchas

* The MSVC payload is whatever Microsoft's manifest currently serves
  (`vsdownload.py` prints the exact version at image build); pin with
  `--msvc-version` for reproducible corpora.
* Wine prefix: the image bakes one for root; running `--user` (recommended, to
  keep workspace files host-owned) auto-creates a throwaway prefix under
  `$HOME` (~10 s once per container).
* `nmake` spawns `cl.exe`/`link.exe` inside Wine; msvc-wine's wrappers handle
  the environment — but heavily parallel builds under Wine are slower than
  native; keep Windows targets small (zlib-scale) at first.
* PDBs must be collected next to the binaries in `results/` (the PE only
  stores a *path* to its PDB); the compile step must copy them like it copies
  `.i` files.
