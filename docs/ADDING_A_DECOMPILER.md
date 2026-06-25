# Adding a Decompiler to DecBench

DecBench evaluates decompilers through a small, stable plugin contract. To add
a new decompiler you implement **one class** with a handful of methods, register
it, and it immediately participates in every metric, the scoreboard, and the
HTML report — no changes to the pipeline are required.

This guide covers: the contract, a minimal working example, registration,
multi-version support, Docker-backed decompilers, and testing.

---

## 1. The contract

A decompiler is a subclass of `decbench.decompilers.base.Decompiler`. The whole
job of a backend is to turn a binary into a `DecompilationResult` — a dict of
per-function `FunctionDecompilation` objects. The metrics consume that result;
they never talk to your decompiler directly.

```python
from decbench.decompilers.base import Decompiler
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult, DecompilerMetadata,
    FunctionDecompilation, LineMapping, VariableInfo,
)
```

### Methods you must implement

| Method | Purpose |
| --- | --- |
| `is_available(self) -> bool` | True if the tool can actually run on this machine (imports succeed / binary on PATH / Docker image present). The registry hides unavailable backends. |
| `get_version(self) -> str \| None` | The realized version string (shown in the report). |
| `decompile_binary(self, binary_path, functions=None, output_dir=None, function_names=None, progress_path=None) -> DecompilationResult` | The core method. |

`discover_functions`, `decompile_function`, and `cleanup` have usable defaults;
override them only if helpful.

### `decompile_binary` signature — match it exactly

The benchmark driver passes two extra keyword arguments beyond the base
abstract signature; accept them:

```python
def decompile_binary(
    self,
    binary_path: Path,
    functions: list[tuple[str, int]] | None = None,  # explicit (name, addr) targets
    output_dir: Path | None = None,
    function_names: set[str] | None = None,           # restrict to these names
    progress_path: Path | None = None,                # checkpoint sink
) -> DecompilationResult:
    ...
```

- **`function_names`** — when non-empty, decompile only these functions (the
  driver uses this to skip bundled libc/gnulib and speed up slow decompilers).
  Fall back to *all* functions if the intersection is empty.
- **`progress_path`** — when set, **atomically pickle a partial
  `DecompilationResult` after each function** so a killed process is still
  recoverable (slow decompilers get SIGKILLed on timeout). See
  `decbench/decompilers/raw/common.py:dump_progress` for a ready-made helper.

### Output requirements that matter for scoring

- **Addresses are ELF-file-space.** Many decompilers report addresses relative
  to a lifted/0-based image. Convert with
  `address = lifted_addr + elf_base`, where `elf_base = min(PT_LOAD vaddr)`.
  This is what makes your addresses line up with DWARF (used by `type_match`).
  Helpers live in `decbench/decompilers/raw/common.py`.
- **Skip non-source functions.** Drop PLT stubs/thunks and CRT helpers
  (`_start`, `__libc_csu_init`, `register_tm_clones`, …) and anything outside
  `.text`. `common.py` provides `SKIP_NAMES`, `SKIP_PREFIXES`, and a `.text`
  range check.
- **Set `decompiler_name = self.id`.** The `id` property is your registered
  name, or `name@version` when a version is pinned (see §4). Using `self.id`
  keeps versioned runs as distinct, comparable columns everywhere downstream.

### What each metric needs (so you know what's worth populating)

| Field on `FunctionDecompilation` | Used by | Required? |
| --- | --- | --- |
| `decompiled_code` (C string) | GED, byte_match | **Yes** — without it nothing scores |
| `address` (ELF-space) | type_match, byte_match | **Yes** |
| `variables: list[VariableInfo]` | type_match | Recommended (else falls back to regex parsing of the C) |
| `line_mappings: list[LineMapping]` | (CFG line attribution) | Optional / best-effort |
| `metadata` (e.g. goto/bool counts) | report extras | Optional |

A backend that only fills `decompiled_code` + correct `address` already scores
on GED and byte_match, and gets a regex-based type_match. Variables and line
maps improve fidelity but are not required.

---

## 2. Minimal working example

```python
@register_decompiler("mydec")
class MyDecompiler(Decompiler):
    name = "mydec"
    display_name = "My Decompiler"

    def is_available(self) -> bool:
        try:
            import mydec  # noqa: F401
            return True
        except ImportError:
            return False

    def get_version(self) -> str | None:
        import mydec
        return mydec.__version__

    def decompile_binary(self, binary_path, functions=None, output_dir=None,
                         function_names=None, progress_path=None):
        from decbench.decompilers.raw.common import (
            elf_min_vaddr, elf_text_range, should_skip_function,
            narrow_to_source, dump_progress,
        )
        import mydec, time

        elf_base = elf_min_vaddr(binary_path)           # add to lifted -> ELF-space
        text_range = elf_text_range(binary_path)
        proj = mydec.open(str(binary_path))

        # Discover (name, lifted_addr), translate to ELF-space, drop CRT/PLT/
        # thunks, then optionally restrict to the project's own source funcs.
        targets = []
        for name, lifted in proj.functions():           # however your tool enumerates
            file_addr = lifted + elf_base
            if should_skip_function(name, file_addr, text_range):
                continue
            targets.append((name, lifted))
        targets = narrow_to_source(
            targets, function_names, backend=self.name, binary_name=binary_path.stem
        )

        funcs: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        start = time.time()
        for name, lifted in targets:
            try:
                code = proj.decompile(lifted)
                funcs[name] = FunctionDecompilation(
                    name=name,
                    address=lifted + elf_base,          # ELF-file-space!
                    decompiled_code=code,
                    line_count=code.count("\n") + 1,
                    variables=[],                       # best-effort; fill if you can
                )
            except Exception:
                failed.append(name)
            if progress_path:                            # crash-safe checkpoint
                dump_progress(progress_path, _partial_result(
                    binary_path, self, funcs, failed, time.time() - start))

        return DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=DecompilerMetadata(
                decompiler_name=self.id,                # versioned-aware key
                decompiler_version=self.get_version(),
                total_time_seconds=time.time() - start,
                failed_functions=failed,
            ),
            functions=funcs,
            output_dir=output_dir,
        )
```

`dump_progress(progress_path, result)` takes a **fully-formed (partial)
`DecompilationResult`** — build one from the functions completed so far (see
`decbench/decompilers/raw/angr_raw.py` for the real pattern; `_partial_result`
above is just a helper that assembles a `DecompilationResult` like the final
return). The shared helpers in `decbench/decompilers/raw/common.py` are:
`elf_min_vaddr`, `elf_text_range`, `in_text`, `should_skip_function`,
`narrow_to_source`, `extract_metrics`, `dump_progress`, and line-mapping
utilities (`line_starts`, `pos_to_line`, `merge_line_addresses`).
```

That is the whole integration. Run it:

```bash
decbench list-decompilers          # mydec shows up, Available = Y
decbench run project.toml -d mydec # full pipeline, all metrics, report
```

---

## 3. Registration

`@register_decompiler("mydec")` adds your class to the global
`DecompilerRegistry`. For the registry to *see* it, the module must be imported
at least once. Backends shipped in-tree are imported from
`decbench/decompilers/__init__.py`; add your import there (or import your module
before calling the registry). Out-of-tree plugins just need to be imported by
your own entry point.

Worked examples in the tree:
- **Native API backends:** `decbench/decompilers/raw/` (`angr_raw.py`,
  `ghidra_raw.py`, `ida_raw.py`, `binja_raw.py`) — drive angr / Ghidra / IDA /
  Binary Ninja directly.
- **Docker-backed backends:** `decbench/decompilers/dockerized.py` (Reko,
  RetDec, r2dec) — run a tool inside a container and parse its C output.

---

## 4. Supporting multiple versions

DecBench can benchmark several versions of the same decompiler as distinct
entries (this powers the report's historical view). You get this for free:

- A spec is `name` or `name@version`, e.g. `ghidra@12.0` and `ghidra@12.1`.
  `DecompilerRegistry.get("ghidra@12.1")` instantiates your class with
  `self.requested_version = "12.1"` and `self.id == "ghidra@12.1"`.
- How a version is *realized* is your backend's choice. Read per-version
  settings from the config with
  `decbench.decompilers.spec.version_settings(self.name, self.requested_version)`.

Example: the Ghidra backend selects which install directory to launch:

```python
from decbench.decompilers.spec import version_settings

settings = version_settings(self.name, self.requested_version)
install_dir = settings.get("install_dir") or os.environ["GHIDRA_INSTALL_DIR"]
```

Configure versions in `~/.config/decbench/decompilers.toml` (or
`$DECBENCH_DECOMPILERS_CONFIG`):

```toml
[ghidra.versions."12.0"]
install_dir = "/opt/ghidra_12.0"
[ghidra.versions."12.1"]
install_dir = "/opt/ghidra_12.1"
```

Then `decbench run ... -d ghidra@12.0 -d ghidra@12.1` produces two comparable
columns and a point on each historical line chart.

---

## 5. Docker-backed decompilers

When a decompiler isn't a Python library (Reko, RetDec, …), subclass
`decbench.decompilers.dockerized.DockerizedDecompiler`. Provide the image tag,
a Dockerfile under `docker/`, and a method that maps the tool's whole-program C
output back onto per-function `FunctionDecompilation`s (pull function
names/addresses from the ELF symbol table so addresses stay ELF-space). Build
the image with:

```bash
decbench decompiler-build retdec
```

`is_available()` should return True only when Docker is present **and** the
image exists locally (don't auto-build inside `is_available`).

---

## 6. Testing your backend

1. **Smoke test** — decompile one small function of one small binary and assert
   non-empty `decompiled_code` and an ELF-space `address`:

   ```python
   dec = DecompilerRegistry.get("mydec")
   assert dec.is_available()
   res = dec.decompile_binary(Path("a.elf"), function_names={"main"})
   assert res.functions["main"].decompiled_code
   ```

2. **Metric sanity** — run `decbench evaluate a.elf -d mydec -s a.i` and confirm
   the three metrics produce values.

3. **Add a pytest** under `tests/` that **skips cleanly** when your tool isn't
   installed (mirror `tests/test_decompilers.py`), so CI stays green on machines
   without it.

That's it — once `is_available()` is true and `decompile_binary` returns a
populated `DecompilationResult`, your decompiler is a first-class citizen of
every DecBench run.
