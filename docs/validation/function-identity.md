# Function identity review follow-up

## Contract

Within a linked binary, concrete DWARF entry addresses identify the targets.
Storage keys remain plain for unique names and become `name@0xADDRESS` for
same-name peers. A subset must not change the binary-wide identity decision.

Benchmark target selection and eval-kit export/ingest now share
`manifest_target_keys`. A qualified request selects that exact address; a legacy
plain request selects every matching target. Requests that cannot resolve stay
explicitly unresolved. Missing results use the canonical selected keys instead
of adding a failed plain-name alias. `name_to_addr` remains a legacy single-address
lookup and must not choose a manifest population.

Source display retains known function addresses even for plain storage keys.
The disk rebuild reader preserves marker addresses and refuses conflicting
cross-producer addresses. Name-only lookup remains available for metadata-free
legacy records. This is best-effort source display, not a source-identity proof
for C++ GED.

`successful_count` counts returned, nonempty, nonfailed records. Missing requested
functions are separate failures, not deductions from the number returned.
Legacy offline GED reevaluation refuses collision-qualified artifacts before
name-based CFG extraction. It does not implement address-aware C++ CFG matching.

## Validation

`.github/workflows/function-identity.yml` checks out the exact submitted head on
push and pull request. It records the checkout/tree and environment, then runs:

- focused identity, eval-kit, artifact, report and offline-GED regression tests;
- compiler-generated ARM/Thumb, MinGW PE/DWARF and LLD ICF fixtures;
- full pytest against both the candidate and pinned main `ae070b8`, in the same
  environment, comparing JUnit identities (including errors and lost passes);
- a stripped LevelDB 1.23 collision through angr and Ghidra, including singleton
  slices with the full identity universe retained.

Rust Joern is pinned to `9fd97f50885202596b125ebd2504e64910874bcb` for this validation;
this change does not update the evaluator parser or adopt its experimental C++ work.

Reproduction after installing the project editable and its documented native
CFG dependency:

```bash
DECBENCH_NO_CACHE=1 pytest -q --no-cov tests/test_cpp_identity*.py \
  tests/test_pr91_review_boundaries.py tests/test_evalkit.py \
  tests/test_materialized.py tests/test_report_extras.py tests/test_reeval_ged.py
python scripts/validate_function_identity.py compare main.xml candidate.xml \
  --output differential.json
GHIDRA_INSTALL_DIR=/path/to/ghidra python scripts/validate_function_identity.py \
  leveldb /path/to/libleveldb.so.1.23.0 --output leveldb.json
```

The historical `ci/pr91b-validation` runs tested `415f9750`, not PR #91's
`8eeceb8` head, and must not be cited as exact-head validation. The newly added
workflow requires a submitted commit before it can provide that evidence.
Local results and remote results must be reported separately.

Full-suite differential success means no new failing identities or lost passing
identities; it is not an assertion that the inherited suite is entirely green.
These probes also do not establish unchanged published C scores. No leaderboard,
result overlay, snapshot or generated site is updated by the follow-up.

## Bounds

PDB/Mach-O transport, official C++ type policy, general C++ source/CFG identity,
and the inherited ELF symbol-name/address byte extraction concern remain outside
this contribution. ICF continues to mean one concrete address per target; alias
policy needs a separate maintainer decision. Frozen publication memberships must
use canonical result keys; this validation does not regenerate any membership or
prove the complete publication/finalization path for legacy ambiguous manifests.
