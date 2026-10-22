# C++ definition and native PDB transport

## Measured motivation

The qualification pilot at data revision
`07dd95dbe6214b8a78fc1e4a55961ab515986489` contains 45 linked images.
Its fixed 250-address native run exposed three qualified C++ definitions
(constructor, assignment operator and comparison operator) that the C grammar
did not index. All 18 MSVC images were recognized as PE but had no readable
DWARF, leaving 97 requested Windows functions outside type measurement.

## Contracts before implementation

* Keep the existing C grammar and C identities for C input. Parse C++
  declarators with a C++ grammar, retain namespace/class qualification and
  reject ambiguous short-name joins. Do not rename code to manufacture C.
* Read PDB 7/MSF, DBI module procedures and TPI/IPI records through one native
  ground-truth owner. No text-dump regex or corpus manifest is an oracle.
* A sibling PDB must match the PE CodeView RSDS GUID and Age, DBI architecture
  and section mapping. Do not follow an embedded absolute producer path.
  Missing, truncated, mismatched or unsupported debug information is unmeasurable.
* Preserve binary VA, RVA, module provenance, exact procedure ranges, type
  identity and storage base separately. Never borrow another overload or ICF
  alias's variable types. Unknown records are retained as exclusion reasons.
* Parameter flags are not parameter ordinals. Do not infer ordinals from record
  order or types. Legacy records without a parameter flag and procedures with
  unsupported variables must not become partially perfect type scores.
* Live ranges are not variable references. Address evidence requires actual
  decoded register/memory references within supported CodeView storage ranges.
  Do not assign every instruction in a lifetime to a variable.
* PDB types expose source spelling and ABI storage. This change connects the
  existing diagnostic matcher; it does not define a new C++ correctness policy.
* A PE format alone does not establish a MinGW compiler. Native MSVC/PDB
  byte_match must abstain until matching compiler provenance/recompilation exists.

## Validation scope

Rerun definition indexing on both tools' fixed 250 outputs. Compare the
unchanged C definitions before/after and inspect the three motivating C++ rows.
Read all 18 real PE/PDB pairs, compare procedure ranges with independently
packaged LLVM inventories, reject wrong GUID/Age and truncated input, and
confirm isolated stripped inputs cannot acquire evaluator PDBs. Run the
unchanged type matcher on the same 97 Windows requests with caches disabled;
report unsupported/ambiguous functions separately from decompiler failures.
Full repository tests and official C++ GED/recompile/Union remain separate gates.

## Current support and eligibility

`binfmt.pdb_info(image)` returns the matching sibling PDB's exact procedures,
source/module provenance, scalar/pointer/reference/array/named aggregate type
records and supported CodeView storage ranges. `NativeCodeResolver`, address
identities, source ownership and source hints consume that same reader. C13's
first-PC source rows are preserved as a candidate set, not a recovered C++
declaration. The legacy singular file/line hint remains present only for one
unambiguous pair. The experimental CFG join may accept multiple pairs only
when all uniquely resolve to the same exact definition in the proven TU; see
[the bounded first-PC qualification](validation/cpp-first-pc-locations.md). Original PDB names are preserved, including backticks and templates.

The reader merges an MSVC legacy home-copy record only with one S_LOCAL having
the same source name, type index and lexical scope. This is an oracle-internal
symbol join; decompiler correspondence remains type-blind. Shadowed variables,
unknown symbols/types/storage pieces, dynamic frames and ICF ambiguities abstain.
PDB frame offsets are retained in transport metadata, not converted to backend
stack coordinates. Parameter ordinals are never invented.

The existing matcher can be exercised with
`MetricConfig(use_cache=False, extra_options={"pdb_abi_diagnostic": True})`.
This explicit diagnostic compares the ABI projection; source spelling remains
separate (for example MSVC `long` is 32 bits and a source reference is passed
as a pointer). Default type scoring abstains because the source-level C++
policy is not qualified. The diagnostic also abstains for producers without
native address evidence. No supported subset of a partially unreadable function
is graded. Cache generation is 21; ELF and Mach-O retain their existing policy.

This is not complete PDB support: parameter classification without S_LOCAL,
member/function pointers, partial storage pieces, OMAP, ARM PDBs, FASTLINK/type
server records and object-field correctness need further work. Neither default
Windows scores nor an official C++ Union/ranking are enabled by this transport.

## Format references

The transport implements public on-disk contracts described by LLVM:
[MSF](https://llvm.org/docs/PDB/MsfFile.html),
[DBI](https://llvm.org/docs/PDB/DbiStream.html),
[CodeView types](https://llvm.org/docs/PDB/CodeViewTypes.html).
LLVM tools are used as independent inspection references, not as a required
runtime parser. The only new package is the C++ Tree-sitter grammar.
