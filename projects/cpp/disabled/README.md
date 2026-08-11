# Disabled C++ targets

These targets are **disabled**: they live here, one level below
`projects/cpp/`, so they fall outside every `projects/cpp/*.toml` evaluation
glob. Both run drivers gather projects with a non-recursive
`d.glob("*.toml")` — `decbench/results_store.py:gather_project_tomls` and
`scripts/compile_all.py:gather_tomls` — so nothing here is picked up, and
`decbench run projects/cpp/*.toml` will not match them either. This mirrors
`projects/cps/disabled/`.

`projects/cpp` deliberately **stays** in both `PROJECT_DIRS` lists. An empty
glob costs nothing, and re-enabling a target is then a one-file move rather
than a code change.

## Why

C++ support is **experimental**. The pipeline runs end-to-end and produces
scores, but the C++ path is much younger than the C one and carries known
limitations that make its numbers harder to interpret. It is disabled by
default so that a routine full run stays C-only and comparable to every
previous run, and so that nobody mistakes an experimental column for a
published result.

Known limitations, all of which apply to **every** decompiler equally rather
than favouring one:

- **Same-name method collapse.** Function results are keyed on the unqualified
  DWARF name, so `leveldb::Table::Next` and `leveldb::Block::Next` share one
  key. On leveldb that is 746 addresses collapsing to 529 distinct names, with
  114 names colliding across 331 addresses (44%). `scripts/run_benchmark.py`
  keeps the longest body per name, so a small method can be scored against an
  unrelated large one. **A C++ project's absolute GED is therefore not
  comparable to a C project's.** Fixing it properly needs qualified names on
  both the Joern side (`fullName`) and the DWARF side (parent-DIE walking).
- **Publish/dataset paths are still `.i`-only.** Several publish and dataset
  export sites glob `*.i` and will silently skip `.ii`, so C++ results are not
  ready to ship to the site or the HuggingFace dataset.
- Joern's C++ frontend is exercised far less here than its C frontend; a
  parse that returns nothing degrades to a warning rather than an error.

## Enabling one

Move it back up a level and run as usual:

```bash
git mv projects/cpp/disabled/leveldb.toml projects/cpp/leveldb.toml
```

Nothing else changes — the support code is on `main` and is always active; only
the target list is gated. When reporting numbers from an enabled C++ target,
state that it is experimental and carry the collapse caveat above.

| target | language | notes |
| --- | --- | --- |
| leveldb | C++17 | shared library + `leveldbutil`; built `-fno-rtti`, so it carries `_ZTV` vtables but no `_ZTI`/`_ZTS` typeinfo |
