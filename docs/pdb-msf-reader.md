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

Tests include synthetic containers and a compiler-produced PE/PDB fixture,
whose information is compared with `llvm-pdbutil` when the tools are available.
The fixture is cross-compiled; it is not a native Windows execution test.

## Public function symbols

`decbench.utils.pdb_publics.read_public_functions(PdbMsf(path))` reads the
modern DBI public address map and its referenced `S_PUB32` function records.
It returns decorated names and section-relative coordinates in symbol record
order, with aliases retained. A missing public stream returns an empty tuple.
Malformed address-map extents, references into record payloads and invalid
function names raise `PdbFormatError`.

These records provide linkage evidence for later native-debug integration.
Resolving an address or a function range requires matching the PE and PDB and
validating the PE section map. See [LLVM DBI](https://llvm.org/docs/PDB/DbiStream.html)
and the [LLVM public symbol stream](https://llvm.org/docs/PDB/PublicStream.html).
