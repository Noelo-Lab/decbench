In specific cases, we most perform fixups (edits) to decompilation output to make evaluation more fair and practical.

### Byte-match fairness (fixup + normalization)

Raw decompiler output rarely recompiles as-is (pseudo-types like `undefined4`,
illegal tokens like `GLIBC_2.2.5::stderr`), so naive recompilation scores almost
everything 0. To measure *logic* recovery fairly, byte-match applies the same
two passes to every decompiler: a **compilability fixup**
(`decbench/metrics/fixup.py`) — a deterministic, gcc-diagnostic-driven
self-repair loop that injects *only* what the compiler reports missing, never
redefining what the decompiler declared (sailr O0 compile rates: ~20–79% raw →
~83–95% fixed, per decompiler) — and **operand normalization**, which blanks
link-time-dependent operands (branch/call targets, `[rip±x]` displacements)
before diffing. Type recovery is scored separately (Type Correctness), so fixing
types just to compile does not inflate this metric; each function also records
whether it recompiled, surfaced as the per-decompiler **compile rate**.