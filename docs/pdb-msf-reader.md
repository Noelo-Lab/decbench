# Experimental PDB MSF transport

`decbench.utils.pdb_msf` reads streams and the information-stream identity from
bounded MSF 7 files. It is a standalone building block; no evaluator, default
metric, cache, or backend uses it.

`decbench.utils.pe_pdb.open_matching_pdb(image, pdb_path)` opens a caller-selected
PDB and requires its GUID and age to equal the PE's sole complete RSDS record.
It reads bounded PE headers, sections and debug records and rejects duplicate
CodeView entries or conflicting payload coordinates. The embedded path is
ignored. The function raises `PdbFormatError` for missing, ambiguous or mismatched
identity and propagates filesystem errors. A matching identity alone gives no
function extent or source ownership.

[PE debug directory](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only)
[LLVM PE/PDB matching](https://llvm.org/docs/PDB/PdbStream.html#matching-a-pdb-to-its-executable)

The reader accepts 512, 1024, 2048, and 4096 byte blocks, a file up to 512 MiB,
at most one million stream entries, and a directory whose block map fits in one
block. Unsupported formats and malformed structures raise `PdbFormatError`;
file-system errors propagate. This is not a comprehensive PDB validator, and
the identity fields alone do not authenticate the file. Types, symbols, source
locations, function ranges, and PE pairing are outside this module's scope.

Tests include synthetic containers and a compiler-produced PE/PDB fixture,
whose information is compared with `llvm-pdbutil` when the tools are available.
The fixture is cross-compiled; it is not a native Windows execution test.
