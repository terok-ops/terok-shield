# SPDX-FileCopyrightText: 2026 terok contributors
# SPDX-License-Identifier: Apache-2.0

"""Basic smoke tests for terok-shield."""

from __future__ import annotations


def test_import() -> None:
    """Package is importable."""
    import terok_shield

    assert hasattr(terok_shield, "__version__")


def test_version_string() -> None:
    """Version is a non-empty string."""
    from terok_shield import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_cli_help(capsys) -> None:
    """CLI prints help without error."""
    from terok_shield.cli import main

    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "terok-shield" in captured.out
