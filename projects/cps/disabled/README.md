# Disabled CPS targets

These targets are **disabled** — they live here, outside `projects/cps/`, so
they are excluded from every `projects/cps/*.toml` evaluation glob (the run
drivers and `decbench run projects/cps/*.toml` will not pick them up).

## Why

These were disabled when decbench had no **C++** support. That reason is now
out of date: C++ works end-to-end (see `projects/cpp/leveldb.toml` and
[docs/benchmarking.md](../../../docs/benchmarking.md#c-targets)). The original
rationale — "pyjoern is C-oriented, so C++ projects produce no `.i` and cannot
be scored" — was wrong on both halves: a C++ translation unit does get
preprocessed, just to `.ii` rather than `.i`, and Joern parses it fine once the
file is handed to its C++ frontend by extension.

What still holds is that neither autopilot has ever been *run* through that
path. They are large cross-compiled Cortex-M/-A firmware, so re-enabling one is
a measurement exercise (build time, Joern parse health on hundreds of C++ TUs,
and the same-name collision caveat that applies to every C++ target), not a
flip of a switch. They stay here until someone does that work.

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
