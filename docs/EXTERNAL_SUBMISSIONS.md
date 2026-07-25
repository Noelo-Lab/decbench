# External Submissions — the sample-set eval kit

DecBench can score a decompiler **without its author ever running DecBench**.
The maintainer exports a self-contained *eval kit* — the frozen **sample-set**
(250 functions) as stripped, anonymized binaries plus a target list — and
publishes it. An outside author decompiles the binaries with their own tool,
drops the C output into the kit's `results/` folder, runs the bundled
`package.py`, and sends back one `results.zip`. The maintainer ingests that zip
as a new **sample-set-only** decompiler column (like `codex`/`claude-code`),
scored by GED / type_match / byte_match exactly like Ghidra or IDA, and it
appears on the [leaderboard](https://decbench.com/).

```
MAINTAINER                     CONTRIBUTOR                    MAINTAINER
decbench evalkit export   →    decompile binaries/       →    decbench evalkit ingest
  kit dir + kit zip              write results/*.c              new dec column in tree
  (publish to HF kits/)          + results.json                 overlays → finalize →
                                 python3 package.py             content edits → site build
                                   → results.zip
```

No decompiler plugin is written (contrast `docs/ADDING_A_DECOMPILER.md` — that
is for tools *we* can run). The whole exchange is two files: the kit zip out,
`results.zip` back.

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
`docs/DATASET_PUBLISHING.md`; the repo's `.gitattributes` already routes
`*.zip` through LFS):

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
the same evaluation path the benchmark uses. The column is marked
`slice_scoped` in its `DecompilerMetadata.extra`, so `finalize_results.py
--audit` expects only manifest-slice coverage from it.

Ingest prints these next steps; do them **before publishing** (the published
numbers are the overlays, not the checkpoint inline values — see the Gotchas
in CLAUDE.md):

```bash
# 1. Refresh the GED + byte_match overlays, extending each script's default
#    decompiler list with the new id (DECBENCH_REEVAL_DECOMPILERS overrides the
#    hardcoded tuple; keep the defaults, add yours):
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
- **type_match uses the code-only parser** (signature → ABI-positioned args +
  locals): submissions carry no `VariableInfo`, so they are scored on the same
  footing as the LLM backends — fair, but structured variable data from a raw
  backend can score slightly differently.
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
