"""Backend-level regressions for C++ same-name function preservation."""

from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler
from decbench.utils.function_identity import insert_function


def test_kuna_records_are_keyed_by_address_not_name() -> None:
    payload = {
        "functions": [
            {"name": "same", "address": 0x1000, "code": "int same(void) { return 1; }"},
            {"name": "same", "address": 0x2000, "code": "int same(void) { return 2; }"},
        ]
    }

    records = RawKunaDecompiler._records_by_address(payload)

    assert set(records) == {0x1000, 0x2000}
    assert records[0x1000]["name"] == "same"
    assert records[0x2000]["name"] == "same"
    assert records[0x1000]["code"] != records[0x2000]["code"]


def test_kuna_same_name_records_can_both_enter_decompilation_result() -> None:
    backend = RawKunaDecompiler()
    payload = {
        "functions": [
            {"name": "same", "address": 0x1000, "code": "int same(void) { return 1; }"},
            {"name": "same", "address": 0x2000, "code": "int same(void) { return 2; }"},
        ]
    }
    records = backend._records_by_address(payload)
    stored = {}

    for address, record in sorted(records.items()):
        function = backend._build_function(record, str(record["name"]), address)
        assert function is not None
        insert_function(stored, function)

    assert set(stored) == {"same@0x1000", "same@0x2000"}
    assert {function.address for function in stored.values()} == {0x1000, 0x2000}
