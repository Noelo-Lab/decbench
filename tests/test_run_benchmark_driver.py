from __future__ import annotations

import pytest

from scripts.run_benchmark import needs_source_cfgs


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
