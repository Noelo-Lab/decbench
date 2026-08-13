"""Regression coverage for the persistent corpus compilation driver."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "compile_all_driver", ROOT / "scripts" / "compile_all.py"
)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def _minimal_pe() -> bytes:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", image, 0x56, 0x0002)  # IMAGE_FILE_EXECUTABLE_IMAGE
    return bytes(image)


def test_count_outputs_includes_linked_pe_images(tmp_path: Path) -> None:
    compiled = tmp_path / "O0" / "firmware" / "compiled"
    compiled.mkdir(parents=True)
    (compiled / "firmware.exe").write_bytes(_minimal_pe())
    (compiled / "firmware.i").write_text("int firmware(void);\n")

    assert DRIVER._count_outputs(tmp_path, "O0", "firmware") == (1, 1)


def test_build_tasks_honors_each_projects_declared_optimization_levels() -> None:
    toml = ROOT / "projects" / "cps" / "u-boot.toml"

    tasks = DRIVER.build_tasks([toml], Path("/tmp/decbench-output"))

    assert [task[1] for task in tasks] == ["O2", "O2-noinline"]
