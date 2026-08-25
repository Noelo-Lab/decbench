# Decompilers — backends, and the three ways to add one

A decompiler column appears on the leaderboard by one of three routes:

1. **A plugin backend** (Part I) — a tool *we* can run: one class implementing
   the `Decompiler` contract, registered in-tree.
2. **An LLM / coding-agent backend** (Part II) — a general coding agent driven
   as a decompiler, one agentic call per function, sample-set-only.
3. **An external submission** (Part III) — a tool we *cannot* run: its author
   scores the exported sample-set eval kit and sends back one `results.zip`.

## Backend families in the tree (`decbench/decompilers/`)

Backends subclass the `Decompiler` ABC (`base.py`) and register via
`@register_decompiler`:

- **Raw / native** (`decompilers/raw/`, the canonical
  `angr`/`ghidra`/`ida`/`binja` in `angr_raw.py`/`ghidra_raw.py`/`ida_raw.py`/
  `binja_raw.py`, plus `kuna_raw.py` and `dewolf_raw.py` +
  `dewolf_driver.py`, an out-of-process backend running in its own venv):
  drive the tools' own APIs directly, **no declib**. `raw/common.py`
  centralises the linked-binary bookkeeping (`elf_min_vaddr`, disjoint ELF/PE
  executable code ranges,
  CRT/PLT/thunk skip sets, `narrow_to_source` function filter, atomic
  `dump_progress` checkpoint, line-mapping helpers). This is the path
  benchmark runs use now.
  Dewolf's independent Binary Ninja sessions are bounded by
  `DECBENCH_DEWOLF_SHARDS` and `DECBENCH_DEWOLF_THREADS` (default 8 × 2) so
  process-level sharding does not multiply Binary Ninja's worker pool without
  limit.
- **Whole-binary** (`raw/manifold_raw.py`: `manifold`): a tool with no
  per-function entry point — one call per binary emits one C translation unit,
  which the backend splits into per-function definitions. It runs manifold
  natively if an executable resolves (`MANIFOLD_BIN` / config / `$PATH`),
  otherwise in the `decbench/manifold` image (`docker/manifold.Dockerfile`,
  built by `decbench decompiler-build manifold`), so a host that only has
  Docker needs nothing else installed. For x86-64 ELF executables importing
  `__libc_start_main`, the same temporary run requests manifold's Clight JSON
  sidecar and consumes only its exact literal-`main` address relation, so that
  function remains addressable after stripping. PE inputs request the same
  sidecar and consume every unique exact final-function name/address relation;
  addresses must lie in an executable PE section, and duplicate names or
  addresses are omitted. This joins two outputs from the same producer rather
  than matching against source names. The sidecar's variables are deliberately
  ignored: they predate final C transformations and are not final-variable
  provenance, so type matching still uses the C/usage fallback and reports no
  native line map.
- **Native or containerized Glaurung** (`raw/glaurung_raw.py`: `glaurung`):
  invokes Glaurung's address-scoped JSON CLI natively when `GLAURUNG_BIN`, the
  decompiler config, or `$PATH` resolves it. Otherwise it runs the immutable
  revision recorded in `decbench/glaurung:latest`, built from source with
  `decbench decompiler-build glaurung`. The raw container has networking
  disabled at runtime and does not receive LLM credentials. The *published*
  `glaurung` column does not come from this backend: it is an external
  sample-set submission (Part III) at `git-fb4ee6b`, flagged
  `external_submission` in its metadata.
- **declib** (`declib_dec.py`, registered as `angr-declib`/`ghidra-declib`/…):
  the original declib-driven backends, kept for comparison.
- **Dockerized** (`dockerized.py`: `reko`/`retdec`/`r2dec`): run a tool in a
  container (or natively for r2dec) and split whole-program C into
  per-function results. Build images with `decbench decompiler-build <name>`;
  Dockerfiles in `docker/`.
- **LLM / coding-agent** (`llm_dec.py`: `codex`, `claude-code`, `kimi-code`):
  Part II below.

Key conventions (all families):

- Addresses are stored in the binary's **linked file space** so they match
  DWARF: ELF uses `lifted + min PT_LOAD vaddr`, while PE uses
  `ImageBase + RVA`. Raw backends normalise per-tool load bases (angr
  `0x400000`, Ghidra `0x100000`, IDA `0x0`) for PIE binaries.
- Functions outside file-backed executable sections, plus PLT/thunks and CRT
  helpers, are skipped.
- `FunctionDecompilation.variables` (`VariableInfo`) carries stack vars/args
  for the type metric. The canonical angr, Binary Ninja, Ghidra, and IDA
  adapters also attach native, 1-based per-function line/address evidence;
  Kuna ingests the same additive evidence from its JSON when available.
  `VariableInfo.arg_index` must be the **ABI position**, not the order the tool
  happens to enumerate its locals in — type_match pairs arguments by that index
  (see [metrics.md](metrics.md#argument-positions-must-be-abi-positions)).
- **Decompiler identity is `name` or `name@version`** (`spec.py`): the
  registry resolves `ghidra@12.1` to a versioned instance whose `.id` flows
  through results/scoreboard/report as a distinct column. Per-version settings
  come from `~/.config/decbench/decompilers.toml`.

After adding a decompiler by ANY route: refresh the metric overlays and
re-finalize before publishing (see
[benchmarking.md](benchmarking.md#overlays-finalize-and-rebuilds--where-the-published-numbers-come-from)),
and add content entries (`decompilers.toml`, and `sample_set_only` in
`site.toml` if applicable) so the site renders the column properly.

---

# Part I — The plugin contract (tools we run)

DecBench evaluates decompilers through a small, stable plugin contract. To add
a new decompiler you implement **one class** with a handful of methods,
register it, and it immediately participates in every metric, the scoreboard,
and the HTML report — no changes to the pipeline are required.

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

`decompile_function` has a usable default (it calls `decompile_binary` with a
single target); override it only if helpful.

### `decompile_binary` signature — match it exactly

The benchmark driver passes two extra keyword arguments beyond the base
abstract signature; accept them:

```python
def decompile_binary(
    self,
    binary_path: Path,
    functions: list[tuple[str, int]] | None = None,  # explicit (name, addr) targets
    output_dir: Path | None = None,
    function_names: set[int] | None = None,           # target ADDRESSES (see below)
    progress_path: Path | None = None,                # checkpoint sink
) -> DecompilationResult:
    ...
```

- **`function_names`** — despite the name, on the benchmark path this is a set of
  **ELF-file-space addresses** (ints — the DWARF `low_pc` of each of the
  project's own source functions; see `scripts/decompile_one.py`). The driver
  hands your backend a *stripped* copy of the binary, so functions are known
  only by address; filter with `narrow_to_source`, which matches by address
  (tolerating the ARM Thumb bit) and fails closed if nothing matches. The parent
  driver also drops any returned function outside the requested address set, so
  a backend mismatch cannot expand a sample or source-only run to unrelated
  functions. Only the dockerized whole-program backends additionally honor
  string names here.
- **`progress_path`** — when set, **atomically pickle a partial
  `DecompilationResult` after each function** so a killed process is still
  recoverable (slow decompilers get SIGKILLed on timeout). See
  `decbench/decompilers/raw/common.py:dump_progress` for a ready-made helper.

### Output requirements that matter for scoring

- **Addresses are linked file-space.** Many decompilers report addresses
  relative to a lifted/0-based image. For ELF, convert with
  `address = lifted_addr + elf_base`, where `elf_base = min(PT_LOAD vaddr)`;
  PE addresses use the header-encoded `ImageBase + RVA`. This is what makes
  addresses line up with DWARF (used by `type_match`). Helpers live in
  `decbench/decompilers/raw/common.py`.
- **Skip non-source functions.** Drop PLT stubs/thunks and CRT helpers
  (`_start`, `__libc_csu_init`, `register_tm_clones`, …) and anything outside
  the binary's disjoint file-backed executable ELF/PE sections. Do not replace
  those ranges with one min/max envelope: gaps and intervening data are not
  code. `common.py` provides `SKIP_NAMES`, `SKIP_PREFIXES`, and the shared
  executable-range check.
- **Set `decompiler_name = self.id`.** The `id` property is your registered
  name, or `name@version` when a version is pinned (see §4). Using `self.id`
  keeps versioned runs as distinct, comparable columns everywhere downstream.

### What each metric needs (so you know what's worth populating)

| Field on `FunctionDecompilation` | Used by | Required? |
| --- | --- | --- |
| `decompiled_code` (C string) | GED, byte_match | **Yes** — without it nothing scores |
| `address` (ELF-space) | type_match, byte_match | **Yes** |
| `variables: list[VariableInfo]` | type_match | Recommended (else parsed out of the C) |
| `line_mappings: list[LineMapping]` | type_match variable correspondence / CFG attribution | Recommended; type-blind usage evidence can supplement or replace it |
| `metadata` (e.g. goto/bool counts) | report extras | Optional |

A backend that only fills `decompiled_code` + correct `address` already scores
on GED and byte_match, and type_match parses variable declarations in its C
(signature → ABI-positioned args + locals). This parsing recovers types and variable
bindings only; production occurrence addresses are never synthesized with a name
regex. Variables and line maps improve fidelity but are not required. Type_match can
use type-blind variable-usage evidence either alone or jointly with native
address/anchor evidence. Each function
records whether its correspondence evidence was `native`, `mixed`, or `fallback_only`;
the site marks mixed/fallback-only Type percentages because conservative heuristic
abstention may undercount recovery.

#### Native line and variable provenance

`LineMapping.line_number` is 1-based in the exact
`FunctionDecompilation.decompiled_code` string stored beside it, not in the
aggregate `.c` file written by `DecompilationResult.to_c_file` (that artifact
adds function headers and preceding bodies). Structured evidence survives in
checkpoint pickles; the standalone `.c` and TOML exports do not preserve it.
Every mapped address is normalized to the binary's linked ELF/PE address space
and should identify a machine instruction in that function. A backend must
collect text and mappings from the same render pass; pairing a Pseudo-C render
with independently enumerated IL rows produces invalid line numbers.

The in-process pipeline and scalable driver pass each complete
`DecompilationResult` through the shared native-provenance sanitizer. It indexes
DWARF function identities and executable regions once per binary, resolves each
function by exact name plus entry address (including split DWARF ranges), and
retains only exact Capstone instruction starts. ARM Thumb-state bits are
normalized only when the cleared address is an exact start; ELF M-profile
attributes enable the Cortex-M decoder mode. ARM instruction state comes from
an odd entry address, an exact or unique named ELF function symbol, or a known
PE ARM machine type. Missing, conflicting, or non-unique state fails closed;
M-profile is a Thumb fallback only when no symbol is available and rejects an
explicit ARM-state symbol. Valid subsets and direct-only variable addresses
survive independently. Empty mapping rows are removed, but variables and
decompiled code are never discarded merely because their address evidence
fails validation. Unmapped signature/declaration line numbers also survive; a
variable line number is removed only when its original mapped row is removed.

The scalable driver intentionally decompiles a stripped worker copy, so its
worker records validation as deferred. After address-to-DWARF relabeling, the
parent validates strictly against the unstripped original before evaluation and
checkpoint persistence. The ordinary in-process pipeline validates strictly at
its adapter boundary. If the exact binary/function context is unavailable at a
final boundary, native address claims fail closed while code and structured
variables remain available to usage/argument/stack matching. Durable metadata
contains only aggregate status, counts, and fixed reason counts—never addresses,
variable/function names, or exception text.

Fresh checkpoint evidence can be checked independently with
`scripts/audit_native_provenance.py`; its strict sample-manifest and
architecture-aware validation contract is documented in
[benchmarking.md](benchmarking.md#auditing-native-line-and-variable-provenance).

The canonical raw adapters use these native sources:

- angr joins `map_ast_to_pos` variable identities to the line-level
  `map_pos_to_addr` evidence, expanding AIL statement addresses to their VEX
  instruction starts. When the identity map is unavailable it uses exact,
  unique C identifiers and abstains on duplicate names. For stripped ARM
  firmware only, the adapter also recognizes the invalid GNU-ld copy-down
  layout where a writable, allocated `.relocate` section has `SHT_REL` but no
  linked symbol table. It retypes that section as ordinary data in an ephemeral
  angr-only copy, preserving the benchmark artifact, section bytes, addresses,
  and the no-symbols invariant; every other ELF layout fails closed unchanged.
- Binary Ninja renders token text and collects row/token expression addresses
  in one Pseudo-C `LinearViewCursor` walk. Structural and warning rows are
  excluded before assigning the global 1-based output line.
- dewolf's out-of-process sidecar walks the final pseudo variables' retained
  Binary Ninja `ssa_name` origins. A name/version origin is accepted only when
  it resolves to one Binary Ninja variable identifier; ambiguous origins are
  omitted. It follows phi/version edges only within that identifier and emits
  the resulting verified machine-instruction starts as direct
  `VariableInfo.addresses` in ELF space. Cross-identifier copies are recorded
  only at the copy instruction and are not treated as identity. Its renderer
  exposes no stable token-to-line map, so it deliberately leaves
  `line_mappings` and variable `line_numbers` empty.
- Ghidra walks the `ClangToken` tree belonging to the same decompile result as
  `getC()`, using HighSymbol IDs for variable occurrences and both token range
  endpoints.
- IDA uses `cfunc_t.get_eamap()` and `find_item_coords()` from the same Hex-Rays
  pseudocode object; one bad item or `BADADDR` is skipped without losing prior
  evidence.
- r2dec stores the exact `pddj` line strings and their instruction offsets, and
  supplements `afvj` variable metadata with all-variable `afvRj` / `afvWj`
  access addresses. Native and container paths apply the same function-range,
  image-base, and ARM Thumb normalization. When the plugin is absent, radare2's
  `pdcj` annotations provide the same line contract; unavailable JSON commands
  transparently fall back to plain `pdd` / `pdc` text. If `afvj` is unavailable
  but JSON line evidence survives, variables parsed from the emitted C are
  joined to those native rows by exact identifier occurrence. The container
  bind-mounts this repository's driver over the image copy and validates its
  versioned output schema, preventing an older image driver from silently
  dropping newly added provenance fields.
- RetDec reconstructs exact C from its annotated JSON token values and validates
  inherited token addresses against DSM instruction starts and function ranges.
  Local identifier tokens carry their LLVM origin address, so the adapter
  recognizes RetDec's validated origin push/pop sequence and attributes each
  occurrence to its enclosing statement address instead.
  If a definition has no usable function-token address, the adapter accepts only
  one exact `function_<hex>` definition whose suffix is a unique DSM function-range
  start and decoded instruction address. Malformed, duplicate, ambiguous, or
  conflicting exact token/name bindings remain unscored; a stray token address
  that is not itself a DSM function entry is treated as missing. Unique annotated
  addresses are merged before the stripped binary's dynamic-symbol filter;
  unrelated dynamic symbols cannot hide them, while name/address conflicts and
  duplicate binding addresses abstain. Binding and requested-address filters keep
  exact addresses for x86, AArch64, and every other non-ARM target. They ignore
  the ARM state bit only when the binary is ARM and an odd entry or ELF M-profile
  attributes prove Thumb execution, so adjacent non-ARM addresses remain distinct.
  The shared native-provenance sanitizer still verifies the relabeled DWARF
  function range and every retained line or variable address.
  Its exact snippet supplies recovered types and ABI argument positions; duplicate
  or shadowed identifiers abstain from variable-occurrence evidence. Missing or
  malformed annotated output falls back to the older plain-C path.
  For audit runs, `DECBENCH_RETDEC_KEEP_SIDECARS=1` publishes the exact JSON/DSM
  pair as one per-binary artifact directory before temporary output is removed.
  Producer outputs must be single-link regular files; missing or conflicting
  artifacts and nonzero annotated invocations fail closed. Result metadata stores
  only relative paths and SHA-256 digests rather than raw bytes. Published files
  are re-opened and rehashed; complete interrupted staging is recovered, while
  partial staging is quarantined and rejected.

The benchmark driver's stripped-to-DWARF relabeling also preserves exact non-ARM
addresses. It accepts an even/odd alias only for a source function whose unstripped
binary metadata proves Thumb state; unavailable or conflicting ARM state fails closed.
- Reko's pinned image captures exact `Identifier` object identities and their
  lower-IR `Statement.Address` values immediately before structuring, then
  intersects them with the identifiers that survive into the final Absyn tree.
  Synthetic def/use/phi/alias statements are excluded and duplicate final names
  abstain. The resulting sidecar carries direct variable addresses and binds
  stripped Reko function names to requested targets by exact entry address. For
  ARM ELF, Reko preserves an odd `e_entry` until its Thumb architecture is
  attached. Even entries use Thumb only when `.ARM.attributes` declares the M
  profile; unknown and A-profile inputs retain Reko's A32 default. The wrapper's
  structured status distinguishes successful output from failed CLI attempts;
  DecBench rejects a status whose mode differs from the host-selected mode.
  Requested-address coverage is counted over unique Thumb-bit-normalized entries,
  and a run that recovers none of those entries is an explicit error.
  Reko's renderer has no stable token-to-line callback, so it deliberately emits
  no line map; older images retain the text/usage fallback. Candidate images can
  be selected with `DECBENCH_REKO_IMAGE` for isolated A/B runs.
- Kuna accepts additive `line_mappings` entries (`line_number`, `addresses`)
  and variable `line_numbers`/`addresses` in `decompile-all --json`. Missing
  fields remain empty for compatibility with older Kuna builds. When the
  benchmark driver supplies its linked source-function addresses, the backend
  forwards them as sorted `--addr` selections so Kuna analyzes only the
  benchmarkable functions in that binary.

Each function records a versioned `variable_occurrence_policy` declaration for
diagnostics. Raw angr, Binary Ninja, Ghidra, IDA, Kuna, and annotated RetDec declare
`exact`; dewolf and Reko declare `direct` because they provide sound variable addresses
without final render rows. r2dec declares `direct` when native variable-access records
survive, `exact` only for its uniquely bound final-C/render-line join, and `unavailable`
when neither source exists. Plain-C RetDec fallback, Glaurung, Manifold, LLM/code-agent
output, imported eval-kit C, and marker-materialized C also declare `unavailable`. An
empty occurrence field remains authoritative under every policy: `exact` describes the
producer contract, not a promise that every variable has an unambiguous surviving
occurrence.

The legacy declib adapters apply a separate fail-closed contract. angr and
Ghidra expose 1-based rows in the exact returned C; IDA exposes zero-based
Hex-Rays coordinates, which DecBench shifts while preserving declib's synthetic
function-entry row. For those three backends, exact parsed identifier bindings
join uniquely named structured variables to validated rows. Duplicate or
shadowed names, C parse errors, malformed rows, addresses outside the function,
and lines outside the rendered text all abstain. Current declib releases can
double-lift angr's line addresses on PIE binaries; `angr-declib` tests both the
reported coordinate and that coordinate plus angr's runtime load base, accepting
an address only when exactly one candidate falls inside the function. Binary
Ninja's declib renderer counts skipped `LinearView` header/warning rows in its
map, so its offsets can drift within a function; `binja-declib` deliberately
emits neither line nor variable-occurrence provenance until declib supplies an
exact-row map. The first three adapters therefore declare the `exact` occurrence
policy, while `binja-declib` declares `unavailable`.

Phoenix is retired and is not a registered backend, but its frozen angr 9.2.213
checkpoints remain reproducible inputs. The former raw Phoenix adapter obtained
both `codegen.text` and `map_pos_to_addr` from the same angr code-generator
object. During TypeMatch checkpoint reevaluation only, DecBench first sanitizes
those saved rows against the selected binary and then joins uniquely bound
identifiers in that unchanged final C to the surviving rows. The join requires
the frozen metadata triplet `decompiler_version="9.2.213"`, `extra.backend="angr"`,
and `extra.via="raw"`; a Phoenix-like name without that origin marker abstains. It
also requires one exact function definition, parseable C, a single declaration and structured
record for the name, unique valid line rows, and at least one mapped occurrence.
It preserves any existing variable evidence and never rewrites the checkpoint.
The join reads only the decompiler's final C, structured variable names, and
sanitized native rows; source/DWARF variable names and recovered or ground-truth
types are not inputs. The established function label is used only to reject a
mismatched final definition. Its `exact` occurrence-policy declaration records the
historical producer contract; the metric independently treats every empty structured
occurrence field as an authoritative abstention.
This historical exception does not restore Phoenix as a producer and is not
applied to another backend merely because it has C text and line-like metadata.

DecLib's lifted zero for PE is backend-dependent: a fresh import may use the
PE ImageBase/header mapping or the start of an encoded section. The adapters
therefore read `deci.binary_base_addr` only after opening the project, require
it to equal the header ImageBase or `ImageBase + section RVA`, and use that
validated origin consistently for target lowering and emitted function/line
addresses. An unreadable PE header, malformed origin, or arbitrary backend
rebase fails closed. ELF continues to use the file's lowest PT_LOAD address,
so a tool's runtime PIE base cannot leak into stored addresses.

##### Glaurung and Manifold: final-AST lineage blockers

An address attached to an early IR statement is not native evidence for a
variable in the final C. The variable can be renamed, folded into another
expression, coalesced with another local, cloned, or deleted before printing.
The final renderer must still know which variable identity and machine
instructions produced each occurrence. Two audited backends do not currently
retain that information:

- Glaurung `fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4` stores a machine VA on
  `LlirInstr`, but `ir/ast.rs::lower_block` calls `lower_op(&ins.op, ...)` and
  drops `ins.va`. Its `Expr` and `Stmt` nodes have no origin field, after which
  expression reconstruction, copy propagation, DCE, condition folding, and
  the DecBench preparation passes rewrite the tree. The JSON command emits
  only `name`, `entry_va`, and `pseudocode`.
- Manifold `b63daf30ccfbcc3a88d7ead117df17e41127f499` keeps instruction-address
  `Node` keys through `SelectedFunction.statements: HashMap<Node, ClightStmt>`.
  Clight emission then assembles those statements into a C tree whose
  `CExpr::Var` contains only a string and whose `CStmt` has no node identity.
  `ForLoopPass`, `VarReducePass`, and `GotoElidePass` run afterward;
  `VarReducePass` applies and discards a local-name coalescing map. The coverage
  audit tracks exact syntax persistence, not node-to-final-variable lineage.

The same blockers remain in the audited upstream heads: Glaurung
`5e16879802d4f1594bf9e8c8286ae420cf3ae869` adds a MIR `source_va`, but its
final `Expr`/`Stmt` nodes and JSON renderer still carry no origin; Manifold's
upstream head is still the pinned `b63daf30ccfbcc3a88d7ead117df17e41127f499`.

Their DecBench adapters deliberately emit no native occurrence addresses or
line maps. Final-name-to-earlier-IR joins would be heuristic, so local-variable
correspondence uses the type-blind usage fallback. ABI argument anchors still
apply when the final C signature exposes them. Metric metadata records
`linemap_present=false`, an `unavailable` producer occurrence policy, and zero
`decompiler_address_variables`; the report's mixed/fallback caveat covers any
score that depended on usage evidence.

The minimal upstream implementation is a provenance-carrying final AST, not a
post-render text matcher:

1. Seed every lowered statement/expression with its set of real machine
   instruction VAs and give every variable a stable identity independent of
   its printed name.
2. Preserve those identities and origin sets through every rewrite. Moving or
   cloning a node preserves its origin; combining nodes unions proven origins;
   deletion drops them. An intentional variable coalescing creates one final
   identity with the union of its members. A synthetic or ambiguous node has no
   mapping.
3. During the same final render that produces the measured C, record the
   1-based output line for each proven statement and variable occurrence.
   Never recover occurrences afterward by matching identifier text.
4. Emit only instruction starts inside the function, normalized to linked
   ELF/PE space. Invalid, out-of-range, duplicate-identity, or stale-render
   evidence must be omitted rather than repaired approximately.

Glaurung can extend each existing per-function JSON record without changing
the CLI shape:

```json
{
  "name": "target",
  "entry_va": 4198400,
  "size": 64,
  "pseudocode": "long target(long arg0) { ... }",
  "line_mappings": [
    {"line_number": 2, "addresses": [4198404]}
  ],
  "variables": [
    {
      "variable_id": "v3",
      "name": "count",
      "type": "long",
      "kind": "stack",
      "arg_index": null,
      "stack_offset": null,
      "line_numbers": [2],
      "addresses": [4198404]
    }
  ]
}
```

Manifold needs a sidecar because its current CLI emits one C translation unit.
Writing `<output.c>.decbench.json` keeps the existing interface and works for
both native and bind-mounted Docker runs. The sidecar must contain a schema
version, SHA-256 of the exact output bytes, and per-function records with
`name`, `entry_va`, exclusive `end_va`, and the same `line_mappings` and
`variables` arrays. Its line numbers are 1-based in the whole translation unit,
and each function record includes its final definition's `start_line` and
`end_line`. The adapter can then verify the hash and translate body lines after
adding DecBench's per-function preamble. Direct variable `addresses` remain
required, so a preamble transformation cannot create variable provenance.

Variable addresses normally come from native occurrence-line evidence. r2dec's
`afvRj` / `afvWj` access lists are stronger than its rendered line offsets and
are therefore retained directly; `line_numbers` records exact address joins
when r2dec emits one. This deliberately supports local-variable matching
without requiring source/decompiler variable names to agree.

Most adapters derive variable addresses from the native addresses on each
occurrence line. RetDec can be narrower: its token stream exposes a temporary
`statement -> variable origin -> statement` address transition around local
identifiers, so the enclosing statement address is retained for each individual
occurrence. This supports local-variable matching without requiring
source/decompiler variable names to agree while avoiding unrelated addresses on
multi-address lines.

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
            elf_min_vaddr, executable_code_ranges, should_skip_function,
            narrow_to_source, dump_progress,
        )
        import mydec, time

        elf_base = elf_min_vaddr(binary_path)           # add to lifted -> ELF-space
        code_ranges = executable_code_ranges(binary_path)
        proj = mydec.open(str(binary_path))

        # Discover functions, drop CRT/PLT/thunks, narrow to the source targets.
        targets = []
        for name, lifted in proj.functions():           # however your tool enumerates
            file_addr = lifted + elf_base
            if should_skip_function(name, file_addr, code_ranges):
                continue
            targets.append((name, file_addr))           # ELF-space, for narrowing
        targets = narrow_to_source(                     # matches by ADDRESS
            targets, function_names, backend=self.name, binary_name=binary_path.stem
        )

        funcs: dict[str, FunctionDecompilation] = {}
        failed: list[str] = []
        start = time.time()
        for name, file_addr in targets:
            try:
                code = proj.decompile(file_addr - elf_base)
                funcs[name] = FunctionDecompilation(
                    name=name,
                    address=file_addr,                  # ELF-file-space!
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
`DecompilationResult`** — build one from the functions completed so far and hand
it to `dump_progress` (see `decbench/decompilers/raw/angr_raw.py` for the real
pattern). The shared helpers in `decbench/decompilers/raw/common.py` include
`elf_min_vaddr` (format-aware: returns the PE ImageBase for MZ binaries, so PE
addresses line up with DWARF too), `executable_code_ranges`,
`should_skip_function`,
`narrow_to_source`, `dump_progress`, and line-mapping utilities.

That is the whole integration. Run it:

```bash
decbench list-decompilers          # mydec shows up, Available = Y
decbench run project.toml -d mydec # full pipeline, all metrics, report
```

## 3. Registration

`@register_decompiler("mydec")` adds your class to the global
`DecompilerRegistry`. For the registry to *see* it, the module must be imported
at least once. Backends shipped in-tree are imported from
`decbench/decompilers/__init__.py`; add your import there (or import your module
before calling the registry). Out-of-tree plugins just need to be imported by
your own entry point.

Worked examples in the tree: the raw backends (`decompilers/raw/`), the
Docker-backed backends (`dockerized.py`, §5), the LLM backends (`llm_dec.py`,
Part II), and the legacy declib backends (`declib_dec.py`).

## 4. Supporting multiple versions

DecBench can benchmark several versions of the same decompiler as distinct
entries — each versioned spec becomes its own comparable column in the results,
scoreboard, and report. You get this for free:

- A spec is `name` or `name@version`, e.g. `ghidra@12.0` and `ghidra@12.1`.
  `DecompilerRegistry.get("ghidra@12.1")` instantiates your class with
  `self.requested_version = "12.1"` and `self.id == "ghidra@12.1"`.
- How a version is *realized* is your backend's choice. Read per-version
  settings from the config with
  `decbench.decompilers.spec.version_settings(self.name, self.requested_version)`.

Example: the Ghidra backend reads `version_settings("ghidra",
self.requested_version)` and launches the `install_dir` it names, falling back
to `$GHIDRA_INSTALL_DIR` when the config has none. Dockerized backends resolve
the configured `image` after the registry binds the requested version, so both
availability checks and runs use that exact image. `DECBENCH_REKO_IMAGE` remains
a higher-priority, explicit override for isolated Reko A/B runs. A configured
r2dec image forces the Docker path; an unversioned r2dec spec retains its normal
native-with-plugin preference and Docker fallback.

Configure versions in `~/.config/decbench/decompilers.toml` (or
`$DECBENCH_DECOMPILERS_CONFIG`):

```toml
[ghidra.versions."12.0"]
install_dir = "/opt/ghidra_12.0"
[ghidra.versions."12.1"]
install_dir = "/opt/ghidra_12.1"

[retdec.versions."5.0"]
image = "decbench/retdec:5.0"

[reko.versions."0.11"]
image = "decbench/reko:0.11"

[r2dec.versions."6.0"]
image = "decbench/r2dec:6.0"
```

`decbench decompiler-build retdec@5.0` builds and tags the image resolved for
that exact spec without changing RetDec's unversioned `:latest` default. The
same applies to other Dockerized specs, including a Reko image selected through
the higher-priority `DECBENCH_REKO_IMAGE` override.

Then `decbench run ... -d ghidra@12.0 -d ghidra@12.1` produces two comparable
columns. (`scripts/ingest_history.py` can additionally fold a versioned run into
another tree's `function_results.json` as history points, though no shipped site
view renders them today.)

## 5. Docker-backed decompilers

When a decompiler isn't a Python library (Reko, RetDec, …), subclass
`decbench.decompilers.dockerized.DockerizedDecompiler`. Provide the image tag,
a Dockerfile under `docker/`, and a method that maps the tool's whole-program C
output back onto per-function `FunctionDecompilation`s. A backend may return an
annotated representation when its CLI exposes native provenance; otherwise pull
function names/addresses from the ELF symbol table so addresses stay ELF-space.
Build the image with:

```bash
decbench decompiler-build retdec
```

`is_available()` should return True only when Docker is present **and** the
image exists locally (don't auto-build inside `is_available`).

Glaurung follows the same explicit-build contract while retaining its raw
address-scoped backend:

```bash
decbench decompiler-build glaurung
decbench list-decompilers
decbench run projects/sailr/bzip2.toml -O O0 -d glaurung
```

The backend prefers a native executable, then falls back to the image. Set
`GLAURUNG_BIN` to an exact executable to force the native route;
`GLAURUNG_IMAGE` retags the container; and `GLAURUNG_REPO` / `GLAURUNG_REF`
select the source revision at build time. `decompiler-build` resolves a branch
or tag to a commit SHA before invoking Docker, and the image records that SHA
at `/opt/glaurung.rev`, so results report the code actually executed. An
invalid explicit `GLAURUNG_BIN` is treated as a configuration error and never
silently falls through to another executable. The default ref is the exact
Glaurung revision used for the submitted sample-set evaluation; set
`GLAURUNG_REF` explicitly to benchmark a different revision. Container runs
use the invoking user's UID and GID so caller-readable binaries remain readable
when their mode is more restrictive than `0644`.

## 6. Testing your backend

1. **Smoke test** — decompile one small function of one small binary and assert
   non-empty `decompiled_code` and an ELF-space `address`:

   ```python
   dec = DecompilerRegistry.get("mydec")
   assert dec.is_available()
   main_addr = 0x1139  # DWARF low_pc of main, ELF-file space (an int, not a name)
   res = dec.decompile_binary(Path("a.elf"), function_names={main_addr})
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

---

# Part II — LLM / coding-agent decompilers (Codex, Claude Code, Kimi Code)

DecBench can benchmark a **general coding agent driven as a decompiler**. For
each target function the agent is handed the (stripped) binary and asked to
reconstruct the original C *by hand* — it is **forbidden from using any
decompiler** and may only use simple disassemblers (`objdump`, `readelf`, `nm`,
`strings`, `xxd`/`od`, `file`, `size`, `c++filt` — `LLM_DECOMPILE_PROMPT` has
the exact list). Its C output is scored by GED / type_match / byte_match exactly
like Ghidra or IDA.

Three backends ship today (`decbench/decompilers/llm_dec.py`):

| id            | tool                        | default model        | credentials |
|---------------|-----------------------------|----------------------|-------------|
| `codex`       | OpenAI Codex CLI            | `gpt-5.6-sol`        | `~/.codex/auth.json` **or** `OPENAI_API_KEY` |
| `claude-code` | Anthropic Claude Code CLI   | `claude-opus-4-8`    | `~/.claude/.credentials.json` **or** `ANTHROPIC_API_KEY` |
| `kimi-code`   | Moonshot Kimi Code CLI      | `kimi-code/k3`       | `~/.kimi-code/credentials/` (OAuth) or `api_key` in `~/.kimi-code/config.toml` |

Pin a model as a version spec so it becomes its own scoreboard column:
`-d codex@gpt-5.6-sol`, `-d claude-code@claude-opus-4-8`, `-d kimi-code@kimi-code/k3`.

On the SITE they are **sample-set-only** decompilers (`[decompilers]
sample_set_only` in site.toml + `visibleDecs()` in app.js).

## The shared prompt

All three backends share one instruction, `LLM_DECOMPILE_PROMPT` in
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

[kimi-code.versions.default]
model = "kimi-code/k3"   # the Kimi K3 alias a Kimi Code OAuth login exposes
# kimi_code_home = "~/.cache/decbench/kimi-code-home"  # isolated KIMI_CODE_HOME
```

Env equivalents: `DECBENCH_LLM_MODEL`, `DECBENCH_LLM_TIMEOUT`,
`DECBENCH_LLM_MAX_FUNCS`, `DECBENCH_LLM_FN_WORKERS` (decompile a binary's
sampled functions concurrently), `DECBENCH_LLM_DOCKER_IMAGE`. Per-decompiler
wall-clock in the driver: `DECBENCH_CODEX_TIMEOUT` /
`DECBENCH_CLAUDE_CODE_TIMEOUT` / `DECBENCH_KIMI_CODE_TIMEOUT` (default 3600s
per binary).

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
- **kimi-code** points `KIMI_CODE_HOME` at `~/.cache/decbench/kimi-code-home`
  (override: `DECBENCH_KIMI_CODE_HOME` / `kimi_code_home`) and passes an empty
  `--skills-dir` (which replaces all discovered skill dirs for the launch), so
  no user/project skill — e.g. a `decompiler` skill driving real decompilers —
  can load; `config.toml` + `credentials/` are synced from `~/.kimi-code` only
  when the host copy is newer, so kimi's in-place OAuth refresh isn't
  clobbered. Kimi Code reads **no** API key from the shell env (`export
  KIMI_API_KEY=...` is ignored) — auth is the OAuth store under
  `$KIMI_CODE_HOME/credentials/` or an `api_key` written in `config.toml`.

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
  -v ~/.kimi-code:/root/.kimi-code:ro \
  -e ANTHROPIC_API_KEY -e OPENAI_API_KEY -e CODEX_HOME=/root/.codex \
  -e KIMI_CODE_HOME=/root/.kimi-code -e HOME=/root \
  decbench/llm-agents:latest <codex exec ... | claude -p ... | kimi -p ...>
```

## How it fits the pipeline

The driver strips each binary and passes DWARF `low_pc` addresses (the agent
sees no symbols — the honest RE setting, identical to what Ghidra/IDA get); the
backend also hands the agent an anonymized `target.bin` copy, so the filename
(`grep`, `nuttx`, …) can't tip an LLM off to recall the source from memory. The
backend labels each function `sub_<addr>`; `run_benchmark._relabel_to_dwarf`
renames the placeholder to the real symbol for function-level evaluation. Missing
line-maps and variables are fine — GED parses the C directly, and type_match
parses the C signature into ABI-positioned arguments plus locals and scores them
through the structured matcher. Missing occurrence provenance remains an explicit
abstention; address-free usage features provide the correspondence fallback. Before
publishing, refresh the metric overlays as with any newly added
decompiler — but note `scripts/reeval_ged.py` and `scripts/reeval_bytematch.py`
hard-code a `DECOMPILERS` tuple that does **not** include the LLM backends
(`codex`/`claude-code`/`kimi-code`):
extend those tuples (and run `scripts/reeval_typematch.py`, which covers every
decompiler in the checkpoints) so the overlays cover the LLM columns, then
`scripts/rebuild_function_data.py`.

---

# Part III — External submissions (the sample-set eval kit)

DecBench can score a decompiler **without its author ever running DecBench**.
The maintainer exports a self-contained *eval kit* — the frozen **sample-set**
(250 functions) as stripped, anonymized binaries plus a target list — and
publishes it. An outside author decompiles the binaries with their own tool,
drops the C output into the kit's `results/` folder, runs the bundled
`package.py`, and sends back one `results.zip`. The maintainer ingests that zip
as a new **sample-set-only** decompiler column (like `codex`/`claude-code`),
scored by GED / type_match / byte_match exactly like Ghidra or IDA, and it
appears on the [leaderboard](https://decbench.com/). The published columns
ingested this way are `manifold`, `glaurung`, and `fission`.

```
MAINTAINER                     CONTRIBUTOR                    MAINTAINER
decbench evalkit export   →    decompile binaries/       →    decbench evalkit ingest
  kit dir + kit zip              write results/*.c              new dec column in tree
  (publish to HF kits/)          + results.json                 overlays → finalize →
                                 python3 package.py             content edits → site build
                                   → results.zip
```

No decompiler plugin is written (contrast Part I — that is for tools *we* can
run). The whole exchange is two files: the kit zip out, `results.zip` back.

## 1. Building and publishing the kit (maintainer)

```bash
decbench evalkit export results/full_run
# -> ./decbench-evalkit-sample-set/  +  ./decbench-evalkit-sample-set.zip
```

Options: `-o OUTPUT_DIR` (default `./decbench-evalkit-<dataset>`),
`--dataset sample-set` (the only supported dataset for now), `--manifest PATH`
(default `<tree>/sample_set_manifest.json`), `--seed N` (anon-name shuffle,
default 1337 — keep it stable so anon names stay comparable across re-exports),
`--zip/--no-zip`, and `--allow-unresolved`.

Export is **strict by default**: any manifest entry that cannot be resolved to
a binary on disk or to a DWARF address is a hard error listing every failure —
a kit must never ship with silently missing targets. `--allow-unresolved`
downgrades to warnings + skip (recorded in the summary). Each shipped binary is
a stripped *copy*, verified byte-identical in `.text` to the original with zero
`.debug_*` sections left.

The kit contains: a contributor `README.md`, `functions.json` (anon binary →
target addresses; the private de-anonymization block is only consumed by
`package.py`/ingest), `binaries/bin_NNN.{elf,exe,so,dll}`, `results/` (format
spec + `results.example.json`), and a standalone stdlib-only `package.py`.

**Publish** to the HF dataset repo (same checkout + conventions as
[dataset-publishing.md](dataset-publishing.md); the repo's `.gitattributes`
already routes `*.zip` through LFS):

```bash
mkdir -p ~/github/decbench-dataset/kits
cp decbench-evalkit-sample-set.zip ~/github/decbench-dataset/kits/
cd ~/github/decbench-dataset
git add kits/decbench-evalkit-sample-set.zip
git commit -m "kits: publish sample-set eval kit"
git push   # LFS objects push with the commit
```

Contributor one-liner to hand out:

```bash
curl -L https://huggingface.co/datasets/noelo-lab/decbench-dataset/resolve/main/kits/decbench-evalkit-sample-set.zip -o kit.zip && unzip kit.zip
```

## 2. What the contributor does (condensed — the kit README is authoritative)

1. Decompile each `binaries/bin_NNN.*` at the addresses listed for it in
   `functions.json` (`public` block). Partial submissions are fine —
   unattempted functions simply score as missing.
2. Write one whole-binary C file per binary into `results/` (all decompiled
   functions concatenated; helper typedefs/structs allowed; no markdown fences
   or prose), plus `results/results.json` mapping each C file to its binary and
   each top-level function identifier in it to the target address:

   ```json
   {
     "decompiler": {"name": "mydec", "version": "1.2.3"},
     "results": {
       "bin_000.c": {
         "binary": "bin_000.elf",
         "functions": {"sub_1234": "0x1234", "fcn_5a10": "0x5a10"}
       }
     }
   }
   ```

3. `python3 package.py` — validates everything (unknown binaries, addresses not
   in the target list, missing `.c` files, duplicate names/addresses are hard
   errors), de-anonymizes binary references, and writes `results.zip` at the
   kit root (`--out PATH` overrides, `--quiet` suppresses warnings).
4. Send back `results.zip` — nothing else.

Addresses are reported in the binary's own header-encoded space (ELF
program-header vaddrs; PE ImageBase + RVA) — i.e. DWARF `low_pc` space. For
PIE ELF that means: IDA (base 0) addresses as-is, Ghidra minus its `0x100000`
base, angr minus its `0x400000` base; ARM firmware and PE as-is; Thumb targets
use the even address (odd tolerated). The kit README spells this out with
examples.

**Malware + blinding policy.** Several kit binaries are compiled-from-source
malware (theZoo corpus), and anonymization means a contributor cannot tell
which — every binary must be treated as hostile: **never execute, analysis
only**. The anonymization itself is good-faith blinding, not secrecy: the
original binaries are public on the HF dataset, so a determined contributor
*could* de-anonymize them; the stripped names/paths just keep honest
evaluations honest (no symbol-driven or memorized-source shortcuts).

## 3. Ingest + publish checklist (maintainer)

```bash
decbench evalkit ingest results.zip results/full_run --id mydec --version 1.2.3
```

**Do not ingest while a `run_benchmark.py` is writing the same tree.** Both
rewrite `checkpoints/<project>.pkl` wholesale and neither takes a lock, so
concurrent writers can lose each other's updates. (Ingest re-reads each
checkpoint immediately before merging, so the window is small, but it is not
zero.)

`--id` must match `^[a-z][a-z0-9-]*$` (no `@`; the submission's own version
string rides in the metadata, not the id). Ingest accepts the packaged
`results.zip` or an unpacked dir of it — a *raw* (un-packaged) `results.json`
is rejected with a pointer to `package.py`. It also checks the kit's
`manifest_sha256` against the tree's current manifest and warns loudly on
**MANIFEST DRIFT** — if the sample-set was re-frozen after the kit went out,
functions the two no longer share are dropped or counted as failures, which
otherwise looks like a bad submission rather than a stale kit. Re-export and
ask for a resubmission when that fires. It resolves each entry back to the
unstripped binary in the tree, splits the whole-binary C, relabels
`sub_<addr>` → DWARF names (address-matched, Thumb/PE tolerant), **drops any
function whose address is not on the manifest for that slice** (counted +
warned), writes `decompiled/<id>_<stem>.c` (+ `.toml`) artifacts, merges the
checkpoints additively (`--force` to overwrite an existing id), and — with
`--evaluate`, the default — computes ged/type_match/byte_match inline through
the same evaluation path the benchmark uses. Ingest discovers both `.i` and
`.ii` units for TypeMatch source address/usage evidence even in a TypeMatch-only
evaluation; it only pays the source-CFG extraction cost when a requested metric
(currently GED) requires CFGs. The column is marked
`slice_scoped` in its `DecompilerMetadata.extra`, so `finalize_results.py
--audit` expects only manifest-slice coverage from it.

Ingest prints these next steps; do them **before publishing** (the published
numbers are the overlays, not the checkpoint inline values — see
[benchmarking.md](benchmarking.md#overlays-finalize-and-rebuilds--where-the-published-numbers-come-from)):

```bash
# 1. Refresh the GED + byte_match overlays, extending each script's default
#    decompiler list with the new id (DECBENCH_REEVAL_DECOMPILERS overrides the
#    hardcoded tuple; keep the defaults, add yours):
DECBENCH_GED_BASELINE=/path/to/frozen-function-results.json \
DECBENCH_GED_HISTORICAL_SLICES=/path/to/frozen-ged-overlay-slices.json \
DECBENCH_REEVAL_DECOMPILERS=angr,ghidra,ida,binja,kuna,r2dec,dewolf,codex,claude-code,mydec \
  python scripts/reeval_ged.py results/full_run 16
DECBENCH_REEVAL_DECOMPILERS=angr,ghidra,ida,binja,kuna,r2dec,dewolf,mydec \
  python scripts/reeval_bytematch.py results/full_run 40

# 2. type_match overlay (covers every decompiler in the checkpoints; no env):
python scripts/reeval_typematch.py results/full_run --emit

# 3. Canonical guarded rebuild (+ audit for silent coverage gaps):
python scripts/finalize_results.py results/full_run --audit

# 4. Content edits (render-time, no re-run):
#    - decbench/rendering/content/site.toml: add "mydec" to
#      [decompilers] sample_set_only (off-preset coverage would look
#      artificially bad under the shared denominator).
#    - decbench/rendering/content/decompilers.toml: add a [[decompiler]] entry
#      (id/display_name/url/license) so the column renders a linked name.

# 5. Re-run the info writers (a function_results rebuild does NOT repopulate
#    them). External kits carry no timing/token facts, so the new column simply
#    has no cost row — run them anyway to keep the blobs current:
python scripts/compute_cost_info.py results/full_run llm_traces
python scripts/compute_dataset_info.py results/full_run

# 6. Rebuild + commit the site:
decbench site build results/full_run -o site/
```

## 4. Limitations

- **byte_match abstains for ARM/PE** on hosts without the cross/MinGW
  toolchains (a non-scoring result, not a 0) — GED + type_match carry those
  slices, same as for every in-house backend.
- **type_match parses the submitted code** for its decompiler-side variables
  and type-blind usage context (submissions carry no `VariableInfo`), while the
  source side receives the tree's preprocessed `.i`/`.ii` units. This matches
  the LLM-backend path; structured variable data from a raw backend can still
  score slightly differently.
- **Sample-set only.** The column renders only on the `sample-set` preset;
  on every other preset its near-zero coverage would be misleading (that is
  exactly what `sample_set_only` gates).
- **Phantom history / the 250 repair.** The originally published 2026-07
  sample-set included a few phantom rows (relabel-duplicate CRT/TLS-callback
  names with no DWARF anchor, unmeasurable for every backend). The manifest
  has since been repaired to 250 fully-resolvable functions
  (`scoring/datasets.py::_scoreable`), and export is strict precisely so a kit
  can never ship a target a contributor cannot legitimately hit. Kits exported
  from a pre-repair manifest need `--allow-unresolved` and will carry fewer
  functions — re-export from the repaired manifest instead. If a future manifest
  picks up dead slots again, repair it the same way (preserves every valid pick,
  refills only the freed slots from their own buckets):

  ```bash
  python scripts/export_sample_set.py results/full_run \
    --base results/full_run/sample_set_manifest.json --drop-unscoreable \
    -o /tmp/manifest_repaired.json     # inspect the diff, then install it
  ```
