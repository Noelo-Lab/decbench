from __future__ import annotations

import pytest

from scripts.run_benchmark import needs_source_cfgs, skip_finalize


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        (None, True),
        (["ged"], True),
        (["type_match", "ged"], True),
        (["type_match"], False),
        (["byte_match"], False),
    ],
)
def test_source_cfg_requirement_tracks_selected_metrics(
    metrics: list[str] | None, expected: bool
) -> None:
    assert needs_source_cfgs(metrics) is expected


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_skip_finalize_accepts_truthy_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DECBENCH_SKIP_FINALIZE", value)
    assert skip_finalize()


def test_skip_finalize_defaults_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DECBENCH_SKIP_FINALIZE", raising=False)
    assert not skip_finalize()
