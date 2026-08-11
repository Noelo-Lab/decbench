"""Contributor-facing text shipped inside an exported eval kit.

Everything here is written for someone who has never seen the DecBench repo:
the kit README (top of the kit), the results-format README (``results/``), and
the filled-in ``results.example.json``. Terminal-friendly markdown only.
"""

from __future__ import annotations

import json
from pathlib import Path

LEADERBOARD_URL = "https://decbench.com"

_KIT_README = """\
# DecBench external eval kit — {dataset}

This kit lets you run YOUR decompiler on DecBench's frozen `{dataset}` slice
({n_functions} functions across {n_binaries} binaries) and submit the output
for scoring on the public leaderboard.

[DecBench]({url}) is a decompiler benchmarking suite. It scores decompilers on
three metrics: structural correctness (CFG graph edit distance against the
original source), type correctness (against DWARF ground truth), and
recompilation byte match (recompile the decompiled C the way the source was
built, compare the machine code). Live leaderboard: {url}

## !!! DO NOT EXECUTE THE BINARIES !!!

**Several binaries in this kit are compiled-from-source malware (theZoo
corpus). Treat EVERY binary as hostile: never execute, analysis only.** The
binaries in `binaries/` are anonymized, but `functions.json` -> `private`
names each one's original project, so you CAN check what you are holding — do
that before doing anything beyond static analysis.

Static analysis (loading them in a disassembler/decompiler) is all this task
requires. Never run them, never `chmod +x` them, never load them in an
emulator or sandboxed VM "just to see".

## Kit contents

| path                            | what                                                  |
| ------------------------------- | ----------------------------------------------------- |
| `README.md`                     | this guide                                            |
| `functions.json`                | per-binary target function addresses (see below)      |
| `binaries/`                     | {n_binaries} stripped + anonymized target binaries    |
| `results/README.md`             | the submission format spec                            |
| `results/results.example.json`  | a filled-in example submission                        |
| `package.py`                    | validates `results/` and produces `results.zip`       |

## A note on the anonymization (blinding)

The anonymization is NOT secrecy — it cannot be. The original binaries are
public (DecBench's dataset ships them on Hugging Face), and this kit's own
`functions.json` -> `private` block maps every anonymous name back to its
project, because `package.py` needs that mapping to de-anonymize your
submission locally.

It is good-faith blinding: with neutral names (`bin_000.elf`, ...) and no
symbols, nothing in the decompilation workflow nudges you toward
special-casing a known target or reading the original source. Please play
along and evaluate the binaries as-is — that is what makes the numbers
comparable to everyone else's.

## Address space (read this before reporting addresses)

Virtual addresses as encoded in the binary's own headers (ELF: program-header
vaddrs at the preferred/link base; PE: ImageBase + RVA). Report addresses in
this space.

`functions.json` -> `public` lists, per binary, the addresses of the functions
to decompile. Your submission must report each function under the SAME
address. If your tool rebases images on load, subtract its load base first:

- PIE ELF in IDA (loads at 0): report the tool's addresses as-is.
- PIE ELF in Ghidra (default image base 0x100000): subtract 0x100000
  (Ghidra `0x101234` -> report `0x1234`).
- PIE ELF in angr (default load base 0x400000): subtract 0x400000
  (angr `0x401234` -> report `0x1234`).
- Non-PIE ELF, ARM firmware, and PE binaries: tools load these at their linked
  base, so report the tool's virtual address as-is.
- ARM/Thumb entry points: report the even address (`0x8008000`); the odd
  Thumb-bit form (`0x8008001`) is tolerated.

When in doubt: every address in `functions.json` -> `public` points at a real
function entry — if the listed addresses land on function starts in your tool,
your address space is right.

## Workflow

1. Load each binary in `binaries/` into your decompiler (analysis only!).
2. Decompile the functions listed for that binary in `functions.json` ->
   `public`. Partial submissions are fine — anything you skip simply scores
   as a miss.
3. For each binary you attempted, write ONE whole-binary `.c` file into
   `results/` (all decompiled functions concatenated; helper typedefs/structs
   allowed; plain C only — no markdown fences, no prose).
4. Describe your files in `results/results.json` — the exact format is in
   `results/README.md`, with a worked example in `results/results.example.json`.
5. Package it:

   ```
   python3 package.py
   ```

   This validates everything and writes `results.zip` next to this README.
   Options: `--out PATH` (write the zip elsewhere), `--quiet` (suppress
   warnings). Validation errors exit non-zero and print what to fix.

6. Send back `results.zip` — nothing else. It contains only your `.c` files
   and a rewritten `results.json`; the binaries stay out of it.

Questions / submissions: open an issue on the DecBench repository (linked from
{url}).
"""

_RESULTS_README = """\
# Submission format (`results/`)

Put your decompiled output here as:

- one `.c` file per binary you attempted, and
- one `results.json` describing them (schema below).

`results.example.json` in this directory is a small filled-in example.

## results.json

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

- Top-level `decompiler`: your tool's `name` (and `version`, if any). The name
  becomes the leaderboard column, so pick something recognizable.
- `results` maps each `.c` FILENAME (as it sits in this directory) to:
  - `binary`: the anonymized binary the file decompiles (a name from the kit's
    `binaries/` directory / `functions.json`). Exactly one `.c` per binary.
  - `functions`: maps a FUNCTION IDENTIFIER to the TARGET ADDRESS it
    implements. The address is a hex string like `"0x1234"` (a bare integer is
    also accepted) and must be one of that binary's addresses from
    `functions.json` -> `public`.

## The .c files

- Each key in `functions` must be the identifier of a top-level function
  definition inside the named `.c` file — whatever your tool calls it
  (`sub_1234`, `FUN_00001234`, ...), as long as the name in the file and the
  key match exactly.
- One whole-binary `.c` per binary: concatenate all of that binary's
  decompiled functions into the one file. Helper typedefs, structs, macros,
  and forward declarations are allowed.
- Plain C only: no markdown fences, no commentary/prose around the code.

## Partial submissions

Allowed and expected. Any target function you do not submit simply scores as
missing — it does not invalidate the rest of the submission. `package.py`
warns about uncovered binaries/addresses but still packages.
"""


def kit_readme(dataset: str, n_binaries: int, n_functions: int) -> str:
    """The kit-root README with the kit's real counts interpolated."""
    return _KIT_README.format(
        dataset=dataset,
        n_binaries=n_binaries,
        n_functions=n_functions,
        url=LEADERBOARD_URL,
    )


def results_readme() -> str:
    """The submission-format spec placed at ``results/README.md``."""
    return _RESULTS_README


def results_example(public: dict[str, list[str]]) -> str:
    """A ``results.example.json`` built from the kit's own first binary.

    Uses the first anonymized binary and (up to) its first two addresses so the
    example is copy-adaptable against the actual kit; falls back to the schema's
    canonical placeholders for an empty mapping.
    """
    if public:
        anon = sorted(public)[0]
        addrs = list(public[anon][:2])
    else:  # pragma: no cover - export never ships an empty kit
        anon, addrs = "bin_000.elf", ["0x1234", "0x5a10"]
    example = {
        "decompiler": {"name": "mydec", "version": "1.2.3"},
        "results": {
            f"{Path(anon).stem}.c": {
                "binary": anon,
                "functions": {f"sub_{a[2:] if a.startswith('0x') else a}": a for a in addrs},
            }
        },
    }
    return json.dumps(example, indent=2) + "\n"
