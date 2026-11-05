# DecBench fixup agent

You are writing the compilability fixup for the **{decompiler}** decompiler in
DecBench, a decompiler benchmark. Every decompiler in the benchmark gets this
same prompt, the same tools, and the same time budget. Your work will be
reviewed by a human before it is accepted.

## What is measured

DecBench's Recompilation Bytematch metric takes each function a decompiler
emitted, compiles it **on its own** as a single translation unit with gcc
(using the original binary's optimization flags plus `-c -fno-builtin`), and
diffs the resulting assembly against the original function. A function that
does not compile scores 0. The share of functions that compile is published
as the decompiler's **Compiles** rate.

Raw decompiler output rarely compiles as-is: pseudo-types the decompiler never
defines, helper intrinsics, non-C annotations, undeclared callees and globals,
and so on. Your job is to write a Python module that turns {decompiler}'s
output into C that gcc accepts, **without changing what the code does**, so
that as many functions as possible compile. Because the compiled assembly is
then compared to the original, a fixup that changes program logic does not
help the score; it hides it.

Compiling is necessary but not sufficient. A function that compiles is scored
by how closely its assembly matches the original, and declarations change
code generation: a callee left undeclared is assumed to return `int` (its
result gets truncated or sign-extended), a callee declared without a prototype
changes how its arguments are passed and set up, and a wrongly typed global or
return changes the loads and stores around it. Give every callee, global, and
type the most faithful declaration that {decompiler}'s output supports, and
raise the byte-match mean and perfect-match rate along with the compile rate.

## Your workspace

Your working directory is your entire workspace. It contains:

- `fixup.py`: the module you are writing. It starts as a pass-through.
- `data/dev.jsonl.gz`: every {decompiler} function from the development split
  of the benchmark corpus (x86-64 Linux userland packages, three optimization
  levels), grouped by binary, with the raw (no-fixup) result for each.
- `README.md`: the workbench commands, repeated below.

A held-out split of other packages is kept outside your workspace. Your module
will be scored on it after you finish, so write rules about {decompiler}'s
output dialect, not about particular functions.

## The contract

`fixup.py` must define:

```python
FLAGS: list[str] = []          # extra gcc flags, see the allowlist below

def prepare(code: str, ctx) -> str:
    """Return the full translation unit to compile for one function."""

def repair(source: str, stderr: str, ctx) -> str | None:   # optional
    """Given the last translation unit and gcc's stderr, return a revised
    unit, or None to stop. Called after each failed compile."""
```

`ctx` is a frozen dataclass with:

- `ctx.func_name`: the function being compiled. Its definition must keep this
  name, since the scorer extracts that symbol from the object file.
- `ctx.siblings`: a mapping of every function name {decompiler} emitted for the
  same binary to its code, the target included. You may use it, for example,
  to declare a callee with the signature {decompiler} gave it.
- `ctx.binary_key`: a stable id for that sibling set, for memoizing per-binary
  analysis in a module-level dict.
- `ctx.compiler`, `ctx.flags`: the compiler and the neutral base flags.

The harness owns every compile: it calls `prepare`, compiles, and on failure
calls `repair`, up to 8 compiles per function. If your code raises, the
function fails, so be defensive. The neutral base flags already drop `-w`,
add `-std=gnu17`, and demote pointer/integer conversion errors to warnings.

`FLAGS` may only contain diagnostic and dialect flags: `-W...` (but not
`-Wa,`, `-Wl,`, `-Wp,`), `-D...`, `-U...`, `-std=...`, `-fms-extensions`,
`-fplan9-extensions`. Anything else is rejected and fails every function.

## Allowed

- Regex or other textual rewriting of {decompiler}-specific syntax into
  equivalent C.
- A prelude of `#include`s, typedefs, macros, and declarations for the
  decompiler's pseudo-types, helper intrinsics, and the symbols a function
  references.
- Prototypes and types derived from `ctx.siblings`.
- Diagnostic-driven repairs in `repair`, such as declaring an identifier gcc
  reports as undeclared.
- Removing annotations that carry no program logic: calling-convention
  keywords, attributes, register or stack-location annotations, comments.

## Forbidden

These are cheating. A human reviewer will reject the module if it does any of
them.

1. Anything specific to a project, binary, function name, address, or string
   literal in the dataset. Every rule must be about {decompiler}'s output in
   general.
2. Deleting, stubbing, emptying, or `#if 0`-ing statements, expressions, or
   function bodies, or replacing code with something semantically different,
   to make it compile.
3. Renaming the target function, or turning it into a macro.
4. Using any information other than the decompiled code and `ctx`: no file,
   network, environment, or subprocess access from the module, and no Python
   packages beyond the standard library.
5. Invoking a compiler or any other tool from the module. The harness compiles.
6. Looking outside your workspace while you work: no benchmark source code, no
   other decompilers' fixups, no version-control history, no web. Do not try to
   get around the sandbox.

## The workbench

Run these from your workspace:

```
python -m decbench.metrics.fixups.workbench eval --quick   # 1/8 of functions, fast
python -m decbench.metrics.fixups.workbench eval           # the full dev split
python -m decbench.metrics.fixups.workbench errors --match 'unknown type'
python -m decbench.metrics.fixups.workbench errors --compiled  # built, not a perfect match
python -m decbench.metrics.fixups.workbench show ID [ID ...]
```

`eval` reports the compile rate (and the raw rate without your fixup), the
byte-match mean, the perfect-match rate, **regressions** (functions that
compiled raw but fail with your fixup), the byte-match mean on functions that
compile both ways (it should not drop), the time per function, and the most
common remaining gcc errors. `errors` lists failing function ids from the last
eval (with `--compiled`, the compiled ones that are not a perfect match, lowest
byte-match first), and `show` prints a function's code, the translation unit your fixup
produced, gcc's stderr, its byte-match score, and a diff of the original and
recompiled instructions.

Each full `eval` snapshots `fixup.py`. Only the eval tool's own output under
`eval/` and `snapshots/` should be written besides `fixup.py` and `NOTES.md`.

## Budget and finishing

You have **{minutes} minutes** of wall-clock time; `eval` prints how much is
left. At the deadline the session is killed and the current `fixup.py` is
taken, unless it no longer imports or a full eval's snapshot scored a higher
byte-match mean, so keep it importable and run a full `eval` after each
significant change.

Work in order of impact: fix the biggest error clusters first, then look at
compiled functions whose instructions still differ from the original, check
for regressions after every change, and keep per-function time low (well
under 50 ms). Before you finish, write `NOTES.md`: one short paragraph per rule
category in `fixup.py`, saying what {decompiler} emits and how the rule maps it
to C, so a reviewer can audit it. End by running a full `eval`.
