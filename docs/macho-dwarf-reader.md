# Experimental thin Mach-O DWARF reader

`decbench.utils.macho_dwarf.macho_dwarf_info` is a low-level reader for a thin
Mach-O linked image and its embedded DWARF or a UUID/CPU/subtype-matched dSYM.
Linked inputs are limited to executable, dynamic library, and bundle images;
external debug companions must be Mach-O dSYM files. It is
not wired into `binfmt.dwarf_info`, decompiler adapters, metrics, cache keys,
the result pipeline, or official rankings. This patch is a first independently
reviewable component; the existing C and ELF/PE evaluation path remains in
place. Integrating it requires a separate change and validation of source and
binary function identity, debug evidence lifetime, and cache behavior.

An explicitly supplied dSYM is always checked. If none is supplied, complete
embedded debug sections take precedence, otherwise the canonical adjacent
`<binary>.dSYM` bundle is considered. Missing, universal, architecture/subtype
or UUID-mismatched inputs return `None`; duplicate DWARF sections also abstain.
UUID matching is necessary identity evidence, not proof that a binary's code
sections have not been modified. The returned DWARF section buffers are owned
in memory. Full DWARF semantic validity, Mach-O function attribution, split
DWARF, universal binary selection and executable correctness are not established
by this API.

## Fixed-project diagnostic

On macOS arm64, the O0 OpenCC stripped image and dSYM from the unofficial C++
qualification dataset revision `07dd95dbe6214b8a78fc1e4a55961ab515986489`
were fetched and verified against that revision's SHA-256 manifest. The reader
found 33 compilation units and 8,911 subprogram DIEs with `DW_AT_low_pc`;
these are raw DIEs, not 8,911 unique or source-owned functions. Supplying the
separately built O2 OpenCC dSYM to the O0 image returned `None`. This is a
reader diagnostic, not a metric or benchmark result. Source information is
used only as evaluator-side evidence; the dataset itself remains marked
`qualified=false` and `scoring_ready=false`.

Focused tests build a real C executable and dSYM on Darwin, verify UUID mismatch
rejection and retain the decoded data after removal of the companion. Other tests
exercise malformed headers, subtype mismatch, UUID absence and duplicate debug
sections. Outside Darwin, the native-tool test is skipped.
