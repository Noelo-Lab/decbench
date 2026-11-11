# Experimental PDB MSF transport

`decbench.utils.pdb_msf` reads streams and the information-stream identity from
bounded MSF 7 files. It is a standalone building block; no evaluator, default
metric, cache, or backend uses it. It does not locate a PDB or match one to a PE.
Before treating PDB contents as ground truth, a future integration must match
the PE CodeView record's GUID and age and define its own evidence contract.

The reader accepts 512, 1024, 2048, and 4096 byte blocks, a file up to 512 MiB,
at most one million stream entries, and a directory whose block map fits in one
block. Unsupported formats and malformed structures raise `PdbFormatError`;
file-system errors propagate. This is not a comprehensive PDB validator, and
the identity fields alone do not authenticate the file. Types, symbols, source
locations, function ranges, and PE pairing are outside this module's scope.

`decbench.utils.pdb_procedures.read_procedure_modules(pdb)` exposes modern DBI
module names, object names and primary CodeView procedure ranges. It keeps
module ordinals and symbol record offsets so names or section coordinates may
repeat without collapsing records. It validates module and symbol extents
and procedure terminators. Linking a primary range to a PE still requires
image pairing and validated section translation. Variable storage, source
ownership and separated code fragments are outside this reader's scope.

[LLVM DBI stream](https://llvm.org/docs/PDB/DbiStream.html)

Tests include synthetic containers and a compiler-produced PE/PDB fixture,
whose information is compared with `llvm-pdbutil` when the tools are available.
The fixture is cross-compiled; it is not a native Windows execution test.
