from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import decbench.decompilers  # noqa: F401
from decbench.decompilers.raw.angr_raw import (
    RawAngrDecompiler,
    _angr_input_binary,
    _runtime_reloc_data_header,
)
from decbench.decompilers.raw.binja_raw import RawBinjaDecompiler
from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
from decbench.decompilers.raw.ida_raw import RawIDADecompiler
from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler
from decbench.models.decompilation import LineMapping, VariableInfo


@pytest.fixture(scope="module")
def live_tiny_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("no C compiler available")
    directory = tmp_path_factory.mktemp("raw_line_provenance")
    source = directory / "tiny.c"
    source.write_text(
        "int add_nums(int a, int b) { int total = a + b; return total; }\n"
        "int main(void) { return add_nums(1, 2); }\n"
    )
    binary = directory / "tiny"
    subprocess.run(
        [compiler, "-g", "-O0", "-fno-inline", "-o", str(binary), str(source)],
        check=True,
    )
    return binary


def _runtime_reloc_elf(*, sh_link: int = 0, physical_address: int = 0x08000000) -> bytes:
    section_headers = 0x200
    section_names = b"\0.relocate\0.shstrtab\0"
    contents = bytearray(section_headers + 3 * 40)
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
    contents[:52] = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        40,
        1,
        0x20000001,
        52,
        section_headers,
        0x5000400,
        52,
        32,
        1,
        40,
        3,
        2,
    )
    contents[52:84] = struct.pack(
        "<IIIIIIII",
        1,
        0x100,
        0x20000000,
        physical_address,
        8,
        8,
        0x6,
        0x1000,
    )
    contents[0x100:0x108] = struct.pack("<II", 0x20000004, 0x101)
    contents[0x108 : 0x108 + len(section_names)] = section_names
    contents[section_headers + 40 : section_headers + 80] = struct.pack(
        "<IIIIIIIIII",
        1,
        9,
        0x3,
        0x20000000,
        0x100,
        8,
        sh_link,
        0,
        4,
        8,
    )
    contents[section_headers + 80 : section_headers + 120] = struct.pack(
        "<IIIIIIIIII",
        11,
        3,
        0,
        0,
        0x108,
        len(section_names),
        0,
        0,
        1,
        0,
    )
    return bytes(contents)


def test_angr_retypes_only_a_temporary_copy_of_runtime_reloc_data(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.elf"
    original = _runtime_reloc_elf()
    binary.write_bytes(original)

    patch = _runtime_reloc_data_header(binary)
    assert patch == (0x22C, b"\x01\0\0\0")

    with _angr_input_binary(binary) as (analysis_path, repair_count):
        patched = analysis_path.read_bytes()
        assert analysis_path != binary
        assert repair_count == 1
        assert patched[0x22C:0x230] == b"\x01\0\0\0"
        assert patched[:0x22C] == original[:0x22C]
        assert patched[0x230:] == original[0x230:]
        assert patched[0x100:0x108] == original[0x100:0x108]
        assert binary.read_bytes() == original

    assert analysis_path is not None
    assert not analysis_path.exists()
    assert binary.read_bytes() == original


def test_angr_loads_the_retyped_runtime_data_section(tmp_path: Path) -> None:
    angr = pytest.importorskip("angr")
    binary = tmp_path / "firmware.elf"
    binary.write_bytes(_runtime_reloc_elf())

    with _angr_input_binary(binary) as (analysis_path, repair_count):
        project = angr.Project(str(analysis_path), auto_load_libs=False)

    assert repair_count == 1
    assert project.arch.name.startswith("ARM")
    assert project.arch.bits == 32
    assert project.loader.main_object.min_addr == 0x20000000
    assert project.loader.memory.load(0x20000000, 8) == struct.pack("<II", 0x20000004, 0x101)
    assert binary.read_bytes() == _runtime_reloc_elf()


@pytest.mark.parametrize(
    "contents",
    [
        _runtime_reloc_elf(sh_link=2),
        _runtime_reloc_elf(physical_address=0x20000000),
    ],
)
def test_angr_runtime_reloc_repair_fails_closed(contents: bytes, tmp_path: Path) -> None:
    binary = tmp_path / "firmware.elf"
    binary.write_bytes(contents)

    assert _runtime_reloc_data_header(binary) is None
    with _angr_input_binary(binary) as (analysis_path, repair_count):
        assert analysis_path == binary
        assert repair_count == 0
        assert analysis_path.read_bytes() == contents


class _Token:
    def __init__(
        self,
        token_type: int,
        text: str,
        *,
        value: int = 0,
        address: int = 0,
        expression: int = 0,
    ) -> None:
        self.type = token_type
        self.text = text
        self.value = value
        self.address = address
        self.il_expr_index = expression

    def __str__(self) -> str:
        return self.text


class _Cursor:
    def __init__(self, lvo: SimpleNamespace) -> None:
        self.chunks = lvo.chunks
        self.index = 0

    @property
    def lines(self) -> list[SimpleNamespace]:
        return self.chunks[self.index]

    def seek_to_begin(self) -> None:
        self.index = 0

    def next(self) -> bool:
        self.index += 1
        return self.index < len(self.chunks)


def test_binja_render_and_evidence_share_one_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    line_types = SimpleNamespace(
        FunctionHeaderStartLineType=1,
        FunctionHeaderEndLineType=2,
        FunctionEndLineType=3,
        AnalysisWarningLineType=4,
        FunctionHeaderLineType=5,
        CodeDisassemblyLineType=6,
    )
    token_types = SimpleNamespace(TagToken=10, LocalVariableToken=11, StackVariableToken=12)
    enums = ModuleType("binaryninja.enums")
    enums.LinearDisassemblyLineType = line_types
    enums.InstructionTextTokenType = token_types

    def row(row_type: int, address: int, *tokens: _Token) -> SimpleNamespace:
        return SimpleNamespace(
            type=row_type,
            contents=SimpleNamespace(address=address, tokens=list(tokens)),
        )

    chunks = [
        [
            row(line_types.FunctionHeaderStartLineType, 0x401000),
            row(line_types.FunctionHeaderLineType, 0x401000, _Token(0, "int f(int x)")),
            row(line_types.FunctionHeaderEndLineType, 0x401000),
        ],
        [
            row(line_types.CodeDisassemblyLineType, 0x401000, _Token(0, "{")),
            row(
                line_types.AnalysisWarningLineType,
                0x401002,
                _Token(0, "warning"),
            ),
            row(
                line_types.CodeDisassemblyLineType,
                0x401004,
                _Token(0, "    return "),
                _Token(token_types.TagToken, "TAG"),
                _Token(
                    token_types.LocalVariableToken,
                    "x",
                    value=7,
                    expression=2,
                ),
                _Token(0, ";"),
            ),
            row(line_types.CodeDisassemblyLineType, 0x401008, _Token(0, "}")),
            row(line_types.FunctionEndLineType, 0x401008),
        ],
    ]

    class Settings:
        def set_option(self, _option: int) -> None:
            pass

    options = SimpleNamespace(
        ShowVariableTypesWhenAssigned=1,
        GroupLinearDisassemblyFunctions=2,
        WaitForIL=3,
    )
    bn = ModuleType("binaryninja")
    bn.DisassemblySettings = Settings
    bn.DisassemblyOption = options
    bn.LinearViewObject = SimpleNamespace(
        single_function_language_representation=lambda *_args: SimpleNamespace(chunks=chunks)
    )
    bn.LinearViewCursor = _Cursor
    monkeypatch.setitem(sys.modules, "binaryninja", bn)
    monkeypatch.setitem(sys.modules, "binaryninja.enums", enums)

    hlil = SimpleNamespace(
        instructions=[],
        get_expr=lambda index: SimpleNamespace(address=0x401006) if index == 2 else None,
    )
    func = SimpleNamespace(
        start=0x401000,
        view=SimpleNamespace(start=0x400000, update_analysis_and_wait=lambda: None),
        address_ranges=[SimpleNamespace(start=0x401000, end=0x401010)],
        hlil=hlil,
    )
    code, mappings, variable_lines = RawBinjaDecompiler._render_c_with_evidence(
        func,
        file_addr=0x1000,
        variable_indices={7: 0},
    )

    assert code == "int f(int x)\n{\n    return x;\n}"
    assert {mapping.line_number: mapping.addresses for mapping in mappings} == {
        1: [0x1000],
        2: [0x1000],
        3: [0x1004, 0x1006],
        4: [0x1008],
    }
    assert variable_lines == {0: {3}}


class _PositionMap:
    def __init__(self, items: list[tuple[int, object]]) -> None:
        self._items = items

    def items(self) -> list[tuple[int, object]]:
        return self._items


def test_angr_native_variable_positions_join_to_instruction_lines() -> None:
    first = object()
    second = object()
    code = "int f(int a) {\n    int aa = a;\n    return aa;\n}"
    variables = [VariableInfo(name="a", type="int"), VariableInfo(name="aa", type="int")]
    codegen = SimpleNamespace(
        map_ast_to_pos=_PositionMap(
            [
                (first, {code.index("a)"), code.index("a;", code.index("aa ="))}),
                (second, [SimpleNamespace(start=code.index("aa;"))]),
            ]
        )
    )
    mappings = [
        LineMapping(line_number=2, addresses=[0x1004]),
        LineMapping(line_number=3, addresses=[0x1008]),
    ]

    RawAngrDecompiler._add_variable_evidence(
        variables,
        [(first, 0), (second, 1)],
        codegen,
        code,
        mappings,
    )

    assert variables[0].line_numbers == [1, 2]
    assert variables[0].addresses == [0x1004]
    assert variables[1].line_numbers == [3]
    assert variables[1].addresses == [0x1008]


def test_angr_line_map_expands_and_rebases_instruction_addresses() -> None:
    element = SimpleNamespace(obj=SimpleNamespace(tags={"ins_addr": 0x5010}))
    mappings = RawAngrDecompiler._extract_line_mappings(
        SimpleNamespace(map_pos_to_addr=_PositionMap([(5, element)])),
        "line one\nline two",
        elf_base=0x1000,
        load_base=0x5000,
        instruction_expansion={0x5010: {0x500C, 0x5010}},
        valid_addresses={0x500C, 0x5010},
    )
    assert mappings == [LineMapping(line_number=1, addresses=[0x100C, 0x1010])]


def test_angr_identifier_fallback_masks_members_literals_and_duplicate_names() -> None:
    code = (
        "int f(int a) {\n"
        "    int aa = a;\n"
        "    obj.a = aa;\n"
        '    char *text = "a aa"; /* a */\n'
        "}"
    )
    variables = [
        VariableInfo(name="a", type="int"),
        VariableInfo(name="aa", type="int"),
        VariableInfo(name="shadow", type="int"),
        VariableInfo(name="shadow", type="int"),
    ]
    mappings = [
        LineMapping(line_number=2, addresses=[0x1004]),
        LineMapping(line_number=3, addresses=[0x1008]),
    ]
    RawAngrDecompiler._add_variable_evidence(
        variables,
        [],
        SimpleNamespace(map_ast_to_pos=None),
        code,
        mappings,
    )
    assert variables[0].line_numbers == [1, 2]
    assert variables[0].addresses == [0x1004]
    assert variables[1].line_numbers == [2, 3]
    assert variables[1].addresses == [0x1004, 0x1008]
    assert variables[2].line_numbers == []
    assert variables[3].line_numbers == []


def test_angr_thumb_detection_is_address_dependent() -> None:
    project = SimpleNamespace(arch=SimpleNamespace(is_thumb=lambda address: bool(address & 1)))
    assert not RawAngrDecompiler._is_thumb_address(project, 0x1000)
    assert RawAngrDecompiler._is_thumb_address(project, 0x1001)


class _AddressSpace:
    def __init__(self, memory: bool) -> None:
        self.memory = memory

    def isMemorySpace(self) -> bool:
        return self.memory


class _Address:
    def __init__(self, offset: int, memory: bool = True) -> None:
        self.offset = offset
        self.space = _AddressSpace(memory)

    def getOffset(self) -> int:
        return self.offset

    def getAddressSpace(self) -> _AddressSpace:
        return self.space


class _GhidraLeaf:
    def __init__(self, line: int, minimum: _Address, maximum: _Address, symbol: int | None):
        self.line = line
        self.minimum = minimum
        self.maximum = maximum
        self.symbol = symbol

    def numChildren(self) -> int:
        return 0

    def getLineParent(self) -> SimpleNamespace:
        return SimpleNamespace(getLineNumber=lambda: self.line)

    def getMinAddress(self) -> _Address:
        return self.minimum

    def getMaxAddress(self) -> _Address:
        return self.maximum

    def isVariableRef(self) -> bool:
        return self.symbol is not None

    def getHighSymbol(self, _high: object) -> SimpleNamespace | None:
        if self.symbol is None:
            return None
        return SimpleNamespace(getId=lambda: self.symbol, getName=lambda: "renamed")

    def getText(self) -> str:
        return "token spelling need not equal the symbol name"


class _GhidraGroup:
    def __init__(self, children: list[object]) -> None:
        self.children = children

    def numChildren(self) -> int:
        return len(self.children)

    def Child(self, index: int) -> object:
        child = self.children[index]
        if isinstance(child, Exception):
            raise child
        return child


def test_ghidra_keeps_min_max_and_skips_nonmemory_siblings() -> None:
    markup = _GhidraGroup(
        [
            _GhidraLeaf(2, _Address(0x5010), _Address(0x5014), 9),
            RuntimeError("broken Java proxy"),
            _GhidraLeaf(2, _Address(0x20, memory=False), _Address(0x20, memory=False), None),
        ]
    )
    result = SimpleNamespace(getCCodeMarkup=lambda: markup)
    body = SimpleNamespace(contains=lambda address: 0x5000 <= address.getOffset() < 0x5100)
    mappings, variable_lines = RawGhidraDecompiler._extract_markup_evidence(
        result,
        object(),
        {9: 0},
        elf_base=0x1000,
        image_base=0x5000,
        code="first\nsecond\n",
        function_body=body,
    )
    assert mappings == [LineMapping(line_number=2, addresses=[0x1010, 0x1014])]
    assert variable_lines == {0: {2}}


def test_ida_bad_address_does_not_erase_prior_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    badaddr = (1 << 64) - 1
    monkeypatch.setitem(sys.modules, "ida_idaapi", SimpleNamespace(BADADDR=badaddr))
    good_item = object()
    bad_item = object()

    def coords(item: object) -> tuple[int, int]:
        if item is bad_item:
            raise ValueError
        return 0, 2

    cfunc = SimpleNamespace(
        entry_ea=0x5010,
        get_pseudocode=lambda: [object()] * 4,
        get_eamap=lambda: {0x5020: [good_item, bad_item], badaddr: [good_item]},
        find_item_coords=coords,
    )
    mappings = RawIDADecompiler._extract_line_mappings(cfunc, 0x1000, 0x5000)
    assert mappings == [
        LineMapping(line_number=1, addresses=[0x1010]),
        LineMapping(line_number=3, addresses=[0x1020]),
    ]


def test_kuna_additive_provenance_is_validated_and_rebased() -> None:
    record = {
        "address": 0x5000,
        "size": 0x20,
        "code": "int f(void) {\n    return x;\n}",
        "line_mappings": [
            {"line_number": 2, "addresses": [0x5004, 0x5008]},
            {"line_number": 99, "addresses": [0x5004]},
            {"line_number": 3, "addresses": [0x6000]},
        ],
        "variables": [
            {
                "name": "x",
                "type": "int",
                "kind": "stack",
                "line_numbers": [2, 99],
                "addresses": [0x5008, 0x6000],
            }
        ],
    }
    function = RawKunaDecompiler()._build_function(record, "f", file_addr=0x1000)
    assert function is not None
    assert function.line_mappings == [LineMapping(line_number=2, addresses=[0x1004, 0x1008])]
    assert function.variables[0].line_numbers == [2]
    assert function.variables[0].addresses == [0x1008]

    no_evidence = RawKunaDecompiler()._build_function(
        {"address": 0x1000, "size": 4, "code": "void f(void) {}", "variables": [{}]},
        "f",
        file_addr=0x1000,
    )
    assert no_evidence is not None
    assert no_evidence.line_mappings == []
    assert no_evidence.variables[0].line_numbers == []
    assert no_evidence.variables[0].addresses == []


def test_kuna_command_passes_sorted_unique_target_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decompiler = RawKunaDecompiler()
    monkeypatch.setattr(decompiler, "_kuna_bin", lambda: "/opt/kuna")

    command = decompiler._build_command(Path("/tmp/program"), [0x2000, 0x1000, 0x2000])
    unfiltered = decompiler._build_command(Path("/tmp/program"))

    assert command[:4] == ["/opt/kuna", "decompile-all", "/tmp/program", "--json"]
    assert command[4:8] == ["--addr", "0x1000", "--addr", "0x2000"]
    assert "--addr" not in unfiltered


def test_kuna_decompile_forwards_source_target_addresses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = tmp_path / "program"
    binary.write_bytes(b"binary")
    decompiler = RawKunaDecompiler()
    selections: list[set[int] | None] = []
    payload = {
        "functions": [
            {
                "name": "sub_1000",
                "address": 0x1000,
                "size": 4,
                "code": "void sub_1000(void) {}",
            }
        ]
    }

    monkeypatch.setattr(decompiler, "_kuna_bin", lambda: "/opt/kuna")
    monkeypatch.setattr(decompiler, "get_version", lambda: "test")
    monkeypatch.setattr(
        decompiler,
        "_run_decompile_all",
        lambda _path, targets: selections.append(set(targets) if targets else None) or payload,
    )
    monkeypatch.setattr(
        "decbench.decompilers.raw.kuna_raw.common.executable_code_ranges",
        lambda _path: ((0x1000, 0x2000),),
    )

    result = decompiler.decompile_binary(
        binary,
        functions=[("sub_1000", 0x1000), ("missing", 0x1100)],
        function_names={0x1000},
    )

    assert selections == [{0x1000, 0x1100}]
    assert list(result.functions) == ["sub_1000"]


def test_kuna_payload_cache_is_scoped_to_target_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decompiler = RawKunaDecompiler()
    commands: list[list[str]] = []

    class Process:
        returncode = 0
        pid = 1

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            return '{"functions": []}', ""

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(
        decompiler,
        "_build_command",
        lambda path, targets: commands.append([str(path), *(hex(address) for address in targets)])
        or ["kuna"],
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())

    assert decompiler._run_decompile_all(Path("program"), {0x2000, 0x1000}) == {"functions": []}
    assert decompiler._run_decompile_all(Path("program"), {0x1000, 0x2000}) == {"functions": []}
    assert decompiler._run_decompile_all(Path("program"), {0x3000}) == {"functions": []}
    assert commands == [
        ["program", "0x1000", "0x2000"],
        ["program", "0x3000"],
    ]


@pytest.mark.skipif(
    os.environ.get("DECBENCH_LIVE_LINE_MAPS") != "1",
    reason="set DECBENCH_LIVE_LINE_MAPS=1 to exercise licensed/native decompilers",
)
@pytest.mark.parametrize("backend", ["angr", "binja", "ghidra", "ida"])
def test_live_raw_backend_provenance(backend: str, live_tiny_binary: Path) -> None:
    script = """
import json
import sys
from pathlib import Path
import decbench.decompilers
from decbench.decompilers.registry import DecompilerRegistry

decompiler = DecompilerRegistry.get(sys.argv[1])
if not decompiler.is_available():
    print(json.dumps({"skip": True}))
    raise SystemExit(0)
result = decompiler.decompile_binary(Path(sys.argv[2]))
function = result.functions.get("add_nums")
if function is None:
    print(json.dumps({"error": sorted(result.functions)}))
    raise SystemExit(0)
print(json.dumps({
    "line_count": function.line_count,
    "mappings": [mapping.model_dump() for mapping in function.line_mappings],
    "variables": [variable.model_dump() for variable in function.variables],
}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, backend, str(live_tiny_binary)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.splitlines()[-1])
    if payload.get("skip"):
        pytest.skip(f"{backend} is unavailable")
    assert "error" not in payload, payload
    mappings = payload["mappings"]
    variables = payload["variables"]
    line_count = payload["line_count"]
    assert mappings
    assert all(1 <= mapping["line_number"] <= line_count for mapping in mappings)

    from decbench.utils.binfmt import _dwarf_function_range

    function_range = _dwarf_function_range(live_tiny_binary, "add_nums")
    assert function_range is not None
    start, end = function_range
    assert all(start <= address < end for mapping in mappings for address in mapping["addresses"])

    from elftools.elf.elffile import ELFFile

    from decbench.experimental.local_variable_distance import instruction_addresses

    with live_tiny_binary.open("rb") as stream:
        instruction_starts = set(instruction_addresses(ELFFile(stream), start, end))
    assert all(
        address in instruction_starts for mapping in mappings for address in mapping["addresses"]
    )

    evidenced = [variable for variable in variables if variable["addresses"]]
    assert evidenced
    line_addresses = {mapping["line_number"]: set(mapping["addresses"]) for mapping in mappings}
    for variable in evidenced:
        assert all(1 <= line <= line_count for line in variable["line_numbers"])
        assert set(variable["addresses"]) <= {
            address
            for line in variable["line_numbers"]
            for address in line_addresses.get(line, set())
        }
