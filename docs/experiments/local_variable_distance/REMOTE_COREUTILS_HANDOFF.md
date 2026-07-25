# Local-variable matching: remote coreutils handoff

## Goal

Measure the correspondence algorithm's accuracy on GNU coreutils, separately
from the proposed recovery score. Run both IDA and Ghidra on binaries with
debug and static symbols removed. Do not report LVED recovery accuracy as
matching precision.

## Implemented

- Source evidence: DWARF variables, scopes, locations, source tokens, line
  tables, and decoded instruction starts.
- Matching: ABI arguments, consensus-calibrated unique stack slots, then
  inverse-frequency weighted address overlap with mutual-best peeling.
- IDA: Hex-Rays ctree variable tokens and `eamap`, persisted as variable
  lines and ELF-space addresses.
- Ghidra: `ClangVariableToken`/`HighSymbol` references and
  `getCCodeMarkup()`, persisted in the same format.
- Generic conversion from a saved `FunctionDecompilation` to matcher evidence.
- Source-function selection can be pinned by DWARF start address to handle
  duplicate static function names.

The normal benchmark driver already gives decompilers stripped copies and
relabels functions afterward. New decompilations now retain the evidence in
their checkpoint pickle. The generated per-binary TOML files do not contain
the full evidence, so preserve `checkpoints/coreutils.pkl`.

## Current evidence

IDA `grep::main`:

- 536 mapped pseudocode lines
- 34 accepted matches from 38 observable source and 140 text-visible IDA vars
- 8/8 audited positive pairs and 2/2 audited negative pairs passed

Ghidra 12.0.1 `grep::main`, with debug and symbol section headers masked:

- 616 mapped pseudocode lines
- all 52 recovered variables have token-derived address evidence
- 24 accepted matches from 38 observable source and 52 Ghidra vars
- LVED 42 and recovery score 0.533; mapping precision is not yet labeled

Reproduce the Ghidra result:

```bash
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
python scripts/demo_ghidra_local_variable_distance.py \
  --check --output /tmp/grep-main-ghidra-lved.json
```

The original IDA proof is under
`docs/experiments/local_variable_distance_grep_main/`.

## Remote setup

```bash
git fetch origin experiment/local-variable-edit-distance
git switch experiment/local-variable-edit-distance
source /home/mahaloz/.virtualenvs/decbench/bin/activate
pip install -e ".[dev]"
export GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1
pytest -o addopts='' tests/test_local_variable_distance.py tests/test_models.py -q
python scripts/demo_ghidra_local_variable_distance.py --check
python scripts/demo_local_variable_distance.py --check
```

Run a cheap O0 decompilation pass before expanding to optimized builds:

```bash
python scripts/compile_all.py results/lved_coreutils 16 coreutils

DECBENCH_OPT_LEVELS=O0 \
DECBENCH_DECOMPILERS=ida,ghidra \
DECBENCH_REDO_DECOMPILERS=ida,ghidra \
DECBENCH_DECOMPILE_ONLY=1 \
DECBENCH_WORKERS=32 \
GHIDRA_INSTALL_DIR=/home/mahaloz/bin/ghidra_12.1 \
python scripts/run_benchmark.py results/lved_coreutils -- coreutils
```

Remove `DECBENCH_OPT_LEVELS=O0` after the O0 audit is sound. Keep
`DECBENCH_REDO_DECOMPILERS` when replacing an older checkpoint that predates
the variable evidence fields.

## Accuracy protocol

Use two clearly labeled lanes.

### Blinded calibration lane

Run a debug-visible decompilation solely to test the matcher. The matcher must
receive renamed variables or otherwise prove name invariance. Use unique
source/decompiler names only after matching as an oracle. Exclude duplicate
names, compiler-generated variables, and rows where the decompiler did not
retain an oracle name.

This lane measures matcher precision but is not a realistic decompiler
recovery result because debug information influenced variable construction.

### Realistic stripped lane

Use the benchmark checkpoint produced above. It measures LVED, coverage,
abstention, and score distributions without name leakage. Establish accuracy
with a stratified manual audit or an independent storage-based oracle. Do not
infer correctness merely from address overlap because that is the signal under
test.

For a storage oracle, compare DWARF location expressions against the
decompiler variable's register/stack storage at each instruction. This is
harder but independent of the line-overlap score and should be the preferred
large-scale oracle.

## Required reporting

Report per decompiler, optimization level, and matching stage:

- accepted matches, correct, incorrect, and oracle-unknown
- precision over oracle-decidable accepted matches
- recall over oracle-decidable source variables
- matcher coverage and abstention rate
- score and runner-up-gap calibration bins
- macro averages by function and micro totals
- bootstrap 95% intervals clustered by function

Freeze `min_overlap` and `ambiguity_margin` before the final test. Use a stable
hash split of functions into tuning and held-out sets. Do not tune thresholds
on the reported test partition.

Run these controls on every result set:

- rename invariance
- disjoint-address overlap goes to zero
- one fake decompiler local increases LVED by one
- every address is an instruction inside the function
- decompiler inputs have no debug or static symbol tables
- repeated runs produce identical pair sets

## Next implementation task

Add a checkpoint scorer that:

1. Loads `results/lved_coreutils/checkpoints/coreutils.pkl`.
2. Resolves each function to its unstripped binary and matching `.i`
   translation unit.
3. Calls `extract_source_evidence(..., function_address=fd.address)`.
4. Calls `extract_decompiler_evidence(fd, backend=decompiler)`.
5. Writes one JSONL record per function plus an aggregate accuracy report.
6. Caches parsed `.i` line-marker content; reparsing it for every function is
   unnecessarily expensive.

Start with O0 and a deterministic sample of roughly 100 functions. Audit that
sample before scaling to all coreutils functions or optimized builds.

## Known limitations

- Source identifier resolution is token-boundary based, not AST based.
- The source instruction decoder currently supports x86/x86-64, which covers
  the intended coreutils run.
- Decompiler variables can split or merge source variables; a one-to-one oracle
  must explicitly label those cases rather than forcing them.
- Exact-name calibration is weak for repeated lexical names and synthetic
  decompiler names.
- Ghidra and IDA may emit declaration-only variables without mapped uses; keep
  these as unmatched rather than inventing addresses.
