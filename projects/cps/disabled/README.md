# Disabled CPS targets

These targets are **disabled** — they live here, outside `projects/cps/`, so
they are excluded from every `projects/cps/*.toml` evaluation glob (the run
drivers and `decbench run projects/cps/*.toml` will not pick them up).

## Why

decbench does not support **C++** yet. The GED metric extracts source control-
flow graphs with pyjoern, which is C-oriented, so C++ projects produce no `.i`
preprocessed sources and cannot be scored on GED. (They also exhibit the usual
C++-from-binary friction — name mangling, `this` pointers, vtables — which makes
type recovery harder.)

| target | dominant language |
| --- | --- |
| ardupilot | C++ (~61% C++, 10% C) |
| px4-autopilot | C++ (~50% C++, 37% C) |

Every other CPS target (`projects/cps/*.toml`) is C and stays enabled.

## Re-enabling

The build recipes here are verified-working (each produces a real ARM Cortex-M
ELF + DWARF). To re-enable a target once C++ support is added, just move its
TOML back up one level:

```bash
git mv projects/cps/disabled/ardupilot.toml projects/cps/ardupilot.toml
```
