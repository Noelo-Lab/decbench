"""CLI registration and dispatch without invoking native decompilers."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import click
import pytest
from click.testing import CliRunner

from decbench.cli import main
from decbench.commands import reporting
from decbench.models.project import Project

COMMANDS = {
    "run",
    "evaluate-tree",
    "evaluate",
    "init-project",
    "list-decompilers",
    "list-metrics",
    "decompiler-build",
    "show",
    "report",
    "site",
    "dataset",
    "download",
    "evalkit",
    "subset",
    "improvements",
}


def test_command_registration_and_help() -> None:
    assert set(main.commands) == COMMANDS
    runner = CliRunner()
    for name, command in main.commands.items():
        result = runner.invoke(main, [name, "--help"])
        assert result.exit_code == 0, result.output
        if isinstance(command, click.Group):
            for child in command.commands:
                result = runner.invoke(main, [name, child, "--help"])
                assert result.exit_code == 0, result.output


def test_init_project_dispatch(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["init-project", "demo", "-o", str(tmp_path)])
    assert result.exit_code == 0, result.output
    project = Project.from_toml(tmp_path / "demo.toml")
    assert project.name == "demo"
    assert project.config.source_dir == "src"


@pytest.mark.parametrize("api", ["download", "main", "cli"])
def test_download_forwards_options(monkeypatch: pytest.MonkeyPatch, api: str) -> None:
    package = ModuleType("decbench_data")
    entry = Mock()
    setattr(package, api, entry)
    monkeypatch.setitem(sys.modules, "decbench_data", package)
    options = {"dest": "out", "repo_path": "local", "include": "scores", "revision": "v1"}
    args = ["download", "sample-set"]
    for name, value in options.items():
        args.extend(["--" + name.replace("_", "-"), value])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    if api == "download":
        entry.assert_called_once_with("sample-set", **options)
    else:
        entry.assert_called_once_with(args)


def test_site_content_resolves_checkout_after_command_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "decbench" / "commands" / "reporting.py"
    module.parent.mkdir(parents=True)
    module.touch()
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\nUnique checkout entry.\n")
    monkeypatch.setattr(reporting, "__file__", str(module))
    content = reporting._site_content()
    assert "Unique checkout entry." in content.views["changelog"].body_html
    (tmp_path / "CHANGELOG.md").unlink()
    assert "Unique checkout entry." not in reporting._site_content().views["changelog"].body_html
