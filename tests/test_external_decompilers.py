"""Tests for the known-but-not-runnable (external submission) decompilers."""

from __future__ import annotations

from pathlib import Path

import pytest

import decbench.decompilers  # noqa: F401  (registers plugins)
from decbench.decompilers.external import EXTERNAL_DECOMPILERS, ExternalDecompiler
from decbench.decompilers.registry import DecompilerRegistry

EXTERNAL_IDS = [spec.id for spec in EXTERNAL_DECOMPILERS]


@pytest.mark.parametrize("dec_id", EXTERNAL_IDS)
def test_external_decompilers_are_registered_but_never_available(dec_id: str) -> None:
    """`decbench list-decompilers` must know the name and still refuse to run it."""
    dec = DecompilerRegistry.get(dec_id)
    assert isinstance(dec, ExternalDecompiler)
    assert dec.runnable is False
    assert dec.is_available() is False
    assert dec_id not in DecompilerRegistry.list_available()


@pytest.mark.parametrize("dec_id", EXTERNAL_IDS)
def test_external_decompile_points_at_the_eval_kit(dec_id: str, tmp_path: Path) -> None:
    """Calling one is a programming error, and the message says what to do instead."""
    with pytest.raises(RuntimeError, match="evalkit ingest"):
        DecompilerRegistry.get(dec_id).decompile_binary(tmp_path / "bin")


def test_runnable_defaults_true_for_real_backends() -> None:
    """The new flag is opt-in: no existing plugin changes behaviour."""
    assert DecompilerRegistry.get("angr").runnable is True


def test_external_specs_match_the_site_registry() -> None:
    """An external id with no `decompilers.toml` entry would render as a raw id."""
    from decbench.rendering.content import load_content

    content = load_content()
    for spec in EXTERNAL_DECOMPILERS:
        entry = content.decompiler(spec.id)
        assert entry is not None, f"{spec.id} missing from decompilers.toml"
        assert entry.display_name == spec.display_name
        assert entry.url == spec.url
